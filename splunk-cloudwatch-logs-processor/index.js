/**
 * Stream events from AWS CloudWatch Logs to Splunk
 *
 * This function streams AWS CloudWatch Logs to Splunk using Splunk's HTTP event collector API.
 *
 * Define the following Environment Variables in the console below to configure
 * this function to stream logs to your Splunk host:
 *
 * 1. SPLUNK_HEC_URL: URL address for your Splunk HTTP event collector endpoint.
 * Default port for event collector is 8088. Example: https://host.com:8088/services/collector
 *
 * 2. SPLUNK_HEC_TOKEN: Token for your Splunk HTTP event collector.
 * To create a new token for this Lambda function, refer to Splunk Docs:
 * http://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector#Create_an_Event_Collector_token
 *
 * For details about Splunk logging library used below: https://github.com/splunk/splunk-javascript-logging
 */

/*
 * Git commit hash: @TAG@
 */

'use strict';

const AWS = require('aws-sdk');
const path = require('path').posix;
const SplunkLogger = require('splunk-logging').Logger;
const zlib = require('zlib');

// Read environment variables specifying the SSM prefix and Splunk cache TTL.
const SSM_PREFIX = process.env.SSM_PREFIX;
const SPLUNK_CACHE_TTL = process.env.SPLUNK_CACHE_TTL;

const ssm = new AWS.SSM();
const ssmCache = {};

exports.handler = (event, context, callback) => {
    console.log('Received event:', JSON.stringify(event, null, 2));
    console.log('Received context:', JSON.stringify(context, null, 2));

    // CloudWatch Logs data is base64 encoded so decode here
    const payload = new Buffer.from(event.awslogs.data, 'base64');

    // CloudWatch Logs are gzip compressed so expand here
    zlib.gunzip(payload, (error, result) => {
        if (error) {
            callback(error);
        } else {
            const parsed = JSON.parse(result.toString('ascii'));
            console.log('Decoded payload:', JSON.stringify(parsed, null, 2));
            getSplunkLogger(parsed, context, callback);
        }
    });
};

const configureLogger = (context, logger, callback) => {
    // Override SplunkLogger default formatter
    logger.eventFormatter = (event) => {
        // Enrich event only if it is an object
        if (typeof event === 'object' && !Object.prototype.hasOwnProperty.call(event, 'awsRequestId')) {
            // Add awsRequestId from Lambda context for request tracing
            event.awsRequestId = context.awsRequestId; // eslint-disable-line no-param-reassign
        }
        return event;
    };

    // Set common error handler for logger.send() and logger.flush()
    logger.error = (error, payload) => {
        console.log('error', error, 'context', payload);
        callback(error);
    };
};

const getSplunkLogger = (parsed, context, callback) => {
    if (parsed.logGroup in ssmCache) {

        const cacheEntry = ssmCache[parsed.logGroup];

        if (cacheEntry && Date.now() <= cacheEntry.expireDT) {
            if ('logger' in cacheEntry) {
                console.log("found in cache for", parsed.logGroup);
                CloudWatchToSplunk(parsed, context, cacheEntry.logger, cacheEntry.sourceType, callback);
                return;
            }

            // FIXME Can this happen? Shouldn't this be a fatal error?
            console.log("found in cache without logger for", parsed.logGroup);
            return;
        }

        // FIXME Would be nice to split a cache miss from an expiration
        console.log("not found in cache or expired for", parsed.logGroup);
    }

    const ssmPath = path.join(SSM_PREFIX, parsed.logGroup + "/");
    // console.log("ssmPath", ssmPath);

    const ssm_params = {
        Names: [
            path.join(ssmPath, 'hec_endpoint'),
            path.join(ssmPath, 'hec_token'),
            path.join(ssmPath, 'sourcetype'),
        ],
        WithDecryption: true
    };

    ssm.getParameters(ssm_params, function(error, ssmData) {
        if (error)
            callback(error);
        else {
            const keyData = {};

            console.log('Data retrieved from SSM:', JSON.stringify(ssmData, null, 2));

            if (ssmData.InvalidParameters.length > 0) {
                const cacheExpireDT = Date.now() + SPLUNK_CACHE_TTL;
                console.log('set expireDT to:', cacheExpireDT);
                ssmCache[parsed.logGroup] = {
                    expireDT: cacheExpireDT
                };
                console.log("wrote to cache without logger for", parsed.logGroup);

                // TODO: Check proper way to do this.
                callback(new Error("Missing required hec_token, hec_endpoint, or sourcetype"));
                return;
            }

            if (ssmData.Parameters) {
                // console.log('SSM parameters:', ssmData.Parameters);

                ssmData.Parameters.forEach((item) => {
                     /* TODO: Failure of index not being 0 should be an error. */
                     if (item.Name.indexOf(ssmPath) == 0) {
                         const name = item.Name.substring(ssmPath.length);
                         keyData[name] = item.Value;
                    }
                }
            )};

            const loggerConfig = {
                token: keyData.hec_token,
                url: keyData.hec_endpoint,
                maxBatchCount: 0, // Manually flush events
                maxRetries: 3,    // Retry 3 times
            };
            // TODO: Check this when we have multiple logGroups to test with.
            console.log('loggerConfig:', JSON.stringify(loggerConfig, null, 2));

            const logger = new SplunkLogger(loggerConfig);
            const cacheExpireDT = Date.now() + SPLUNK_CACHE_TTL;

            console.log('set expireDT to:', cacheExpireDT);
            ssmCache[parsed.logGroup] = {
                logger: logger,
                expireDT: cacheExpireDT,
                sourceType: keyData.sourcetype
            };

            console.log("wrote to cache for", parsed.logGroup);
            // FIXME: Maybe we should just pass in whole keyData object to
            // extract logger and sourcetype inside function.
            CloudWatchToSplunk(parsed, context, logger, keyData.sourcetype, callback);
        }
    });
};

const CloudWatchToSplunk = (parsed, context, logger, sourcetype, callback) => {
    // First, configure logger to automatically add Lambda metadata and to hook into Lambda callback
    configureLogger(context, logger, callback); // eslint-disable-line no-use-before-define

    let identifier = "";
    let prefix = "";
    let index = parsed.logStream.lastIndexOf("/");

    if (index >= 0) {
        prefix = parsed.logStream.substring(0, index);
        identifier = parsed.logStream.substring(index+1);
    }

    let count = 0;
    if (parsed.logEvents) {
        parsed.logEvents.forEach((item) => {
            /* Send item message to Splunk with optional metadata properties such as time, index, source, sourcetype, and host.
            - Change "item.timestamp" below if time is specified in another field in the event.
            - Set or remove metadata properties as needed. For descripion of each property, refer to:
            http://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTinput#services.2Fcollector */

            const log = {
                message: item.message,
                metadata: {
                    time: item.timestamp ? new Date(item.timestamp).getTime() / 1000 : Date.now(),
                    host: parsed.logGroup,
                    source: parsed.logStream,
                    sourcetype: sourcetype,
                    //index: 'main',
                },
             };

            console.log(log);
            logger.send(log);
            count += 1;
        });
    }
    // Send all the events in a single batch to Splunk
    logger.flush((err, resp, body) => {
        // Request failure or valid response from Splunk with HEC error code
        if (err || (body && body.code !== 0)) {
            // If failed, error will be handled by pre-configured logger.error() below
        } else {
            // If succeeded, body will be { text: 'Success', code: 0 }
            console.log('Response from Splunk:', body);
            console.log(`Successfully processed ${count} log event(s).`);
            callback(null, count); // Return number of log events
        }
    });
};
