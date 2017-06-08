const crypto = require('crypto');
const AWS = require('aws-sdk');

const encrypted = process.env.secret;
let decrypted;


function processEvent(event, context, callback) {
    let hash, hmac;
    const signature = event.headers['X-Hub-Signature'];
    const calculatedSignature = `sha1=${crypto.createHmac('sha1', decrypted).update(event.body, 'utf-8').digest('hex')}`;
    console.log('the calculated signature....');
    console.log(calculatedSignature);
    if (signature === calculatedSignature) {
        console.log('Happy path');
        callback(null, {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            body: event.body
        });
    } else {
        console.log('not good');
        callback(null, {
            "statusCode": 401,
            "message": {"message": "none shall pass."}
        })
    }
}

module.exports.githubListener = (event, context, callback) => {
    if (decrypted) {
        processEvent(event, context, callback);
    } else {
        // Decrypt code should run once and variables stored outside of the function
        // handler so that these are decrypted once per container
        const kms = new AWS.KMS();
        kms.decrypt({ CiphertextBlob: new Buffer(encrypted, 'base64') }, (err, data) => {
            if (err) {
                console.log('Decrypt error:', err);
                return callback(err);
            }
            decrypted = data.Plaintext.toString('ascii');
            processEvent(event, context, callback);
        });
    }
};
