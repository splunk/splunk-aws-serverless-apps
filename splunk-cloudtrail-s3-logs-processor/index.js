/**
 * Forward Cloudtrail Logs from S3 to Splunk via AWS Lambda
 * 
 * This function streams access logs to Splunk Enterprise using Splunk's HTTP event collector API.
 *
 * Define the following Environment Variables in the console below to configure
 * this function to log to your Splunk host:
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
    maxRetries: 3, // Retry 3 times
};

const SplunkLogger = require('splunk-logging').Logger;
const aws = require('aws-sdk');
const zlib = require('zlib');

const logger = new SplunkLogger(loggerConfig);
const s3 = new aws.S3({ apiVersion: '2006-03-01' });

exports.handler = (event, context, callback) => {
    console.log('Received event:', JSON.stringify(event, null, 2));

    // First, configure logger to automatically add Lambda metadata and to hook into Lambda callback
    configureLogger(context, callback); // eslint-disable-line no-use-before-define

    // Get the S3 object from the S3 put event
    const bucket = event.Records[0].s3.bucket.name;
    const key = decodeURIComponent(event.Records[0].s3.object.key.replace(/\+/g, ' '));
    const params = {
        Bucket: bucket,
        Key: key,
    };
    s3.getObject(params, (error, data) => {
        if (error) {
            console.log(error);
            const message = `Error getting object ${key} from bucket ${bucket}. Make sure they exist and your bucket is in the same region as this function.`;
            console.log(message);
            callback(message);
        } else {
            console.log(`Retrieved log: LastModified="${data.LastModified}" ContentLength=${data.ContentLength}`);
            const payload = data.Body;
            // CloudTrail Logs are gzip compressed so expand here
            zlib.gunzip(payload, (error, result) => {
                if (error) {
                    console.log(error);
                    callback(error);
                } else {
                    // const parsed = payload.toString('ascii');
                    const parsed = JSON.parse(result.toString('ascii'));
                    console.log('Decoded payload:', JSON.stringify(parsed, null, 2));

                    let count = 0;
                    if (parsed.Records) {
                        parsed.Records.forEach((item) => {
                            /* Send item message to Splunk with optional metadata properties such as time, index, source, sourcetype, and host.
                            - Change "item.timestamp" below if time is specified in another field in the event.
                            - Set or remove metadata properties as needed. For descripion of each property, refer to:
                            http://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTinput#services.2Fcollector */
                            logger.send({
                                message: JSON.stringify(item),
                                metadata: {
                                    time: item.eventTime ? new Date(item.eventTime).getTime() / 1000 : Date.now(),
                                    host: 'serverless',
                                    source: `lambda:${context.functionName}`,
                                    sourcetype: 'aws:cloudtrail',
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
