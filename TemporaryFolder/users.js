var AWS = require("aws-sdk");
var fs = require("fs");

//    ./tmp.json file contains the configuration details like region, endpoint, accessKeyId, secretAccessKey in json format.
var config = JSON.parse(fs.readFileSync('tmp.json', 'utf8'));

AWS.config.update({
    region: config.AWS.region,
    endpoint: config.AWS.endpoint,
    accessKeyId: config.AWS.accessKeyId,
    secretAccessKey: config.AWS.secretAccessKey
  });

var dynamodb = new AWS.DynamoDB();



// To create a new Table

var params = {
    TableName : "Users",
    KeySchema: [       
        { AttributeName: "personalEmail", KeyType: "HASH"}
    ],
    AttributeDefinitions: [       
        { AttributeName: "personalEmail", AttributeType: "S" }
    ],
    ProvisionedThroughput: {       
        ReadCapacityUnits: 5, 
        WriteCapacityUnits: 5
    }
};

dynamodb.createTable(params, function(err, data) {
    if (err) {
        console.error("Unable to create table. Error JSON:", JSON.stringify(err, null, 2));
    } else {
        console.log("Created table. Table description JSON:", JSON.stringify(data, null, 2));
    }
});



// To Delete a Table

// var params = {
//     TableName : "Users"
// };

// dynamodb.deleteTable(params, function(err, data) {
//     if (err) {
//         console.error("Unable to delete table. Error JSON:", JSON.stringify(err, null, 2));
//     } else {
//         console.log("Deleted table. Table description JSON:", JSON.stringify(data, null, 2));
//     }
// });