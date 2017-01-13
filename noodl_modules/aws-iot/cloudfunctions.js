"use strict";

function CloudFunctions() {  
}

CloudFunctions.prototype.call = function(name,params,args) {
  var lambda = new AWS.Lambda();
  var params = {
    FunctionName: name,
    InvocationType: 'RequestResponse',    
    Payload: JSON.stringify(params)
  };
  lambda.invoke(params, function(err, data) {
    if (err) {
      console.log('Cloud function error:',err);
      args&&args.failure&&args.failure(err.message);
      return;
    }
    console.log('Cloud function success:',data);
    args&&args.success&&args.success(JSON.parse(data.Payload));
  });
}

CloudFunctions.instance = new CloudFunctions();

module.exports = CloudFunctions;