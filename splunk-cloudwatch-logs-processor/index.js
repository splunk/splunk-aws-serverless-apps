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

'use strict';

const loggerConfig = {
    url: process.env.SPLUNK_HEC_URL,
    token: process.env.SPLUNK_HEC_TOKEN,
    maxBatchCount: 0, // Manually flush events
    maxRetries: 3,    // Retry 3 times
};

const SplunkLogger = require('splunk-logging').Logger;
const zlib = require('zlib');

const logger = new SplunkLogger(loggerConfig);

exports.handler = (event, context, callback) => {
    console.log('Received event:', JSON.stringify(event, null, 2));

    // First, configure logger to automatically add Lambda metadata and to hook into Lambda callback
    configureLogger(context, callback); // eslint-disable-line no-use-before-define

    // CloudWatch Logs data is base64 encoded so decode here
    const payload = Buffer.from(event.awslogs.data, 'base64');
    // CloudWatch Logs are gzip compressed so expand here
    zlib.gunzip(payload, (error, result) => {
        if (error) {
            callback(error);
        } else {
            const parsed = JSON.parse(result.toString('utf8'));
            console.log('Decoded payload:', JSON.stringify(parsed, null, 2));
            let count = 0;
            if (parsed.logEvents) {
                parsed.logEvents.forEach((item) => {
                    /* Send item message to Splunk with optional metadata properties such as time, index, source, sourcetype, and host.
                    - Change "item.timestamp" below if time is specified in another field in the event.
                    - Set or remove metadata properties as needed. For descripion of each property, refer to:
                    http://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTinput#services.2Fcollector */
                    logger.send({
                        message: item.message,
                        metadata: {
                            time: item.timestamp ? new Date(item.timestamp).getTime() / 1000 : Date.now(),
                            host: 'serverless',
                            source: `lambda:${context.functionName}`,
                            sourcetype: 'httpevent',
                            //index: 'main',
                        },
                    });

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
        }
    });
};

const configureLogger = (context, callback) => {
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
