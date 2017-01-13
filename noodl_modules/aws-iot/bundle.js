(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
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
},{}],2:[function(require,module,exports){
var UserManagement = require('./usermanagement');
var ThingState = require('./thingstate');
var CloudFunctions = require('./cloudfunctions');

/* ---------------------------------------------------------------------------- 
   Custom broker to connect to AWS IoT device gateway
   ---------------------------------------------------------------------------- */
function SigV4Utils() { }

SigV4Utils.sign = function (key, msg) {
    var hash = CryptoJS.HmacSHA256(msg, key);
    return hash.toString(CryptoJS.enc.Hex);
};

SigV4Utils.sha256 = function (msg) {
    var hash = CryptoJS.SHA256(msg);
    return hash.toString(CryptoJS.enc.Hex);
};

SigV4Utils.getSignatureKey = function (key, dateStamp, regionName, serviceName) {
    var kDate = CryptoJS.HmacSHA256(dateStamp, 'AWS4' + key);
    var kRegion = CryptoJS.HmacSHA256(regionName, kDate);
    var kService = CryptoJS.HmacSHA256(serviceName, kRegion);
    var kSigning = CryptoJS.HmacSHA256('aws4_request', kService);
    return kSigning;
};

SigV4Utils.getSignedUrl = function (protocol, host, uri, service, region, accessKey, secretKey, sessionToken) {
    var time = moment().utc();
    var dateStamp = time.format('YYYYMMDD');
    var amzdate = dateStamp + 'T' + time.format('HHmmss') + 'Z';
    var algorithm = 'AWS4-HMAC-SHA256';
    var method = 'GET';

    var credentialScope = dateStamp + '/' + region + '/' + service + '/' + 'aws4_request';
    var canonicalQuerystring = 'X-Amz-Algorithm=AWS4-HMAC-SHA256';
    canonicalQuerystring += '&X-Amz-Credential=' + encodeURIComponent(accessKey + '/' + credentialScope);
    canonicalQuerystring += '&X-Amz-Date=' + amzdate;
    canonicalQuerystring += '&X-Amz-SignedHeaders=host';

    var canonicalHeaders = 'host:' + host + '\n';
    var payloadHash = SigV4Utils.sha256('');
    var canonicalRequest = method + '\n' + uri + '\n' + canonicalQuerystring + '\n' + canonicalHeaders + '\nhost\n' + payloadHash;


    var stringToSign = algorithm + '\n' + amzdate + '\n' + credentialScope + '\n' + SigV4Utils.sha256(canonicalRequest);
    var signingKey = SigV4Utils.getSignatureKey(secretKey, dateStamp, region, service);
    var signature = SigV4Utils.sign(signingKey, stringToSign);

    canonicalQuerystring += '&X-Amz-Signature=' + signature;
    if (sessionToken) {
        canonicalQuerystring += '&X-Amz-Security-Token=' + encodeURIComponent(sessionToken);
    }

    var requestUrl = protocol + '://' + host + uri + '?' + canonicalQuerystring;
    return requestUrl;
}

Noodl.defineBroker({
  id:'awsiot',
  name:'AWS IoT',
  settings:[
    { 
          group: "MQTT",
          type: "string",
          name: "mqttAWSIoTEndpoint",
          displayName: "Endpoint"
      },
      {
          group: "MQTT",
          type: "string",
          name: "mqttAWSIoTAccessKey",
          displayName: "Access Key"
      },
      {
          group: "MQTT",
          type: "string",
          name: "mqttAWSIoTSecretKey",
          displayName: "Secret Key"
      }     
  ],
  url:function(options) {
    var service = 'iotdevicegateway';
    var region = options.awsIoTRegion||'us-east-1';
    var secretKey = options.mqttAWSIoTSecretKey;
    var accessKey = options.mqttAWSIoTAccessKey;
    var sessionToken;
    if (AWS && AWS.config.credentials) {
        accessKey = AWS.config.credentials.accessKeyId;
        secretKey = AWS.config.credentials.secretAccessKey;
        sessionToken = AWS.config.credentials.sessionToken;
    }
    if (accessKey === undefined || secretKey === undefined) return;
    if (accessKey === "" || secretKey === "") return;
    var canonicalUri = '/mqtt';
    var host = options.mqttAWSIoTEndpoint;

    return SigV4Utils.getSignedUrl('wss', host, canonicalUri,
        service, region, accessKey, secretKey, sessionToken);
  },
})

/* ---------------------------------------------------------------------------- 
   Sign In User
   ---------------------------------------------------------------------------- */
Noodl.defineNode({
    name: "UserManagmenetSignIn",
    displayNodeName: "Sign In User",
    category: "AWS IoT",
    initialize: function () {
        this._internal.working = false;
    },
    inputs: {
        username: {
            displayName: 'Username',
            group: 'User data',
            type: 'string',
            set: function (value) {
                this._internal.username = value;
            }
        },
        password: {
            displayName: 'Password',
            group: 'User data',
            type: 'string',
            set: function (value) {
                this._internal.password = value;
            }
        },
        signin: {
            displayName: 'Sign In',
            group: 'Actions',
            valueChangedToTrue: function () {
                var _this = this;

                this._internal.working = true;
                this.flagOutputDirty('working');

                UserManagement.instance.signIn(this._internal.username, this._internal.password, {
                    success: function () {
                        _this._internal.working = false;
                        _this.flagOutputDirty('working');

                        _this.sendSignalOnOutput('success');
                    },
                    userNotConfirmed: function () {
                        _this._internal.working = false;
                        _this.flagOutputDirty('working');

                        _this.sendSignalOnOutput('userNotConfirmed');
                    },
                    newPasswordRequired: function () {
                        _this._internal.working = false;
                        _this.flagOutputDirty('working');

                        _this.sendSignalOnOutput('newPasswordRequired');
                    },
                    failure: function (err) {
                        _this._internal.working = false;
                        _this.flagOutputDirty('working');
                                                
                        _this._internal.failureMessage = err;
                        _this.flagOutputDirty('failureMessage');
                        _this.sendSignalOnOutput('failure');
                    }
                });
            }
        }
    },
    outputs: {
        success: {
            displayName: "Success",
            type: "signal",
            group: "Signals"
        },
        userNotConfirmed: {
            displayName: "User Not Confirmed",
            type: "signal",
            group: "Signals"
        },
        newPasswordRequired: {
            displayName: "New Password Required",
            type: "signal",
            group: "Signals"
        },
        failure: {
            displayName: "Failure",
            type: "signal",
            group: "Signals"
        },
        failureMessage: {
            displayName: "Failure Message",
            type: "string",
            group: "Result",
            getter: function () {
                return this._internal.failureMessage;
            }
        },
        working: {
            displayName: "Working",
            type: "boolean",
            group: "Status",
            getter: function () {
                return this._internal.working;
            }
        }
    },
    prototypeExtensions: {
    },
    settings:[
        {
            group:"AWS Cognito",
            type:"string",
            displayName:"User Pool Id",
            name:"userManagementAWSUserPoolId",
        },
        {
            group:"AWS Cognito",
            type:"string",
            displayName:"Client App Id",
            name:"userManagementAWSUserPoolClientAppId",
        },
        {
            group:"AWS Cognito",
            type:"string",
            displayName:"Identity Pool Id",
            name:"userManagementAWSIdentityPoolId",
        },                       
    ]
});

/* ---------------------------------------------------------------------------- 
   User session
   ---------------------------------------------------------------------------- */
Noodl.defineNode({
    name: "UserManagmenetUserSession",
    displayNodeName: "User Session",
    category: "AWS IoT",
    initialize: function() {
      var _this = this;

      function flagSessionStateDirty() {
        _this.flagOutputDirty('sessionState');        
        _this.flagOutputDirty('isValid');
        _this.flagOutputDirty('isInvalid');
        _this.flagOutputDirty('isPending');
        _this.flagOutputDirty('userId');
      }

      UserManagement.instance.events.on('userManagementCredentialsReceived',function() {
        flagSessionStateDirty();
        _this.sendSignalOnOutput('signedIn');
      });

      UserManagement.instance.events.on('userManagementCachedCredentialsNotAvailable',function() {
        flagSessionStateDirty();
      });

      UserManagement.instance.events.on('userManagementSignedOut',function() {
        flagSessionStateDirty();
        _this.sendSignalOnOutput('signedOut');
      });

      UserManagement.instance.events.on('userManagementSessionLost',function() {
        flagSessionStateDirty();
        _this.sendSignalOnOutput('sessionLost');
      });  
               
    },
    inputs: {
        signOut: {
            displayName: 'Sign Out',
            group: 'Actions',
            valueChangedToTrue: function() {
              UserManagement.instance.signOut();
            }
        }                           
    },
    outputs: {
        sessionLost: {
            displayName: "Session Lost",
            type: "signal",
            group: "Signals"
        },      
        signedOut: {
            displayName: "Signed Out",
            type: "signal",
            group: "Signals"
        },
        isValid: {
            displayName: "Is valid",
            type: "boolean",
            group: "Status",
            getter: function() {
              return UserManagement.instance.getSessionState() === UserManagement.SessionState.Valid;
            }
        },
        isInvalid: {
            displayName: "Is Invalid",
            type: "boolean",
            group: "Status",
            getter: function() {
              return UserManagement.instance.getSessionState() === UserManagement.SessionState.Invalid;
            }
        },
        isPending: {
            displayName: "Is Pending",
            type: "boolean",
            group: "Status",
            getter: function() {
              return UserManagement.instance.getSessionState() === UserManagement.SessionState.Pending;
            }
        },
        sessionState: {
            displayName: "Session State",
            type: "string",
            group: "Status",
            getter: function() {
              return UserManagement.instance.getSessionState();
            }
        },                                 
        signedIn: {
            displayName: "Signed In",
            type: "signal",
            group: "Signals"
        },
        userId: {
            displayName: "User Id",
            type: "string",
            group: "User Info",
            getter: function() {
                return UserManagement.instance.getUserId();
            }
        }       
    },
    prototypeExtensions: {
    }
})

/* ---------------------------------------------------------------------------- 
   Cloud function (Lambda)
   ---------------------------------------------------------------------------- */
var CloudFunction = {
    name: "Cloud Function",
    category: "AWS IoT",
    color: "javascript",  
    usePortAsLabel: "name",      
    initialize: function() {
    },
    inputs: {
        name: {
            displayName: 'Name',
            group: 'General',
            type: 'string',
            set: function(value) {
              this._internal.name = value;
            }
        },
        callPayload: {
            type:{name:'stringlist',allowEditOnly:true},
            displayName:'Call Payload',
            group:"Call Payload",
            set:function(value) {
                this._internal.callPayload = value.split(',');             
            }
        },
        responsePayload: {
            type:{name:'stringlist',allowEditOnly:true},
            displayName:'Response Payload',
            group:"Response Payload",
            set:function(value) {
                this._internal.responsePayload = value.split(',');             
            }
        },                         
        call: {
            displayName: 'Call',
            group: 'Actions',
            valueChangedToTrue: function() {
              var _this = this;

              CloudFunctions.instance.call(this._internal.name,{},{
                success:function() {
                  _this.sendSignalOnOutput('success');
                },
                failure:function(err) {
                  _this._internal.failureMessage = err;
                  _this.flagOutputDirty('failureMessage');
                  _this.sendSignalOnOutput('failure');
                }
              });
            }
        }
    },
    outputs: {
        success: {
            displayName: "Success",
            type: "signal",
            group: "Signals"
        },               
        failure: {
            displayName: "Failure",
            type: "signal",
            group: "Signals"
        },
        failureMessage: {
            displayName: "Failure Message",
            type: "string",
            group: "Result",
            getter: function() {
              return this._internal.failureMessage;
            }
        }
    },
    prototypeExtensions: {
    }
};

function updatePorts(nodeId, parameters, editorConnection) {

    var callPayload = parameters.callPayload;
    var responsePayload = parameters.responsePayload;
    
    var ports = [];

    // Add call payload inputs
    callPayloadItems = callPayload ? callPayload.split(',') : [];
    for(var i in callPayloadItems) {
        var p = callPayloadItems[i];

        ports.push({
            type:{name:'*',
                allowConnectionsOnly:true},
            plug:'input',
            group:'Call Payload',
            name:p,
        });
    }

    // Add response payload outputs
    responsePayloadItems = responsePayload ? responsePayload.split(',') : [];
    for(var i in responsePayloadItems) {
        var p = responsePayloadItems[i];

        ports.push({
            type:{name:'*',
                allowConnectionsOnly:true},
            plug:'output',
            group:'Response Payload',
            name:p,
        });
    }    

    var hash = JSON.stringify(ports);
    if(statesPortsHash[nodeId] !== hash) { // Make sure we don't resend the same port data
        statesPortsHash[nodeId] = hash;
        editorConnection.sendDynamicPorts(nodeId, ports);
    }
}

Noodl.defineNode({
    node: CloudFunction,
    setup: function(context, graphModel) {

        if(!context.editorConnection || !context.editorConnection.isRunningLocally()) {
            return;
        }

        graphModel.on("nodeAdded.Cloud Function", function(node) {
            if(node.parameters.callPayload || node.parameters.resposePayload) {
                updatePorts(node.id, node.parameters, context.editorConnection);
            }
            node.on("parameterUpdated", function(event) {
                if(event.name === "callPayload" || event.name === "resposePayload") {
                    updatePorts(node.id,  node.parameters, context.editorConnection);
                }
            });
        });
    }    
});

/* ---------------------------------------------------------------------------- 
   Cloud function (Lambda)
   ---------------------------------------------------------------------------- */
Noodl.defineNode({
  name: "UserManagmenetSignUp",
  displayNodeName: "Sign Up User",
  category: "AWS IoT",
  initialize: function () {
    this._internal.attributes = {};

    this._internal.working = false;
  },
  inputs: {
    username: {
      displayName: 'Username',
      group: 'User data',
      type: 'string',
      set: function (value) {
        this._internal.username = value;
      }
    },
    password: {
      displayName: 'Password',
      group: 'User data',
      type: 'string',
      set: function (value) {
        this._internal.password = value;
      }
    },
    email: {
      displayName: 'Email',
      group: 'User data',
      type: 'string',
      set: function (value) {
        this._internal.attributes['email'] = value;
      }
    },
    signUp: {
      displayName: 'Sign Up',
      group: 'Actions',
      valueChangedToTrue: function () {
        var _this = this;

        this._internal.working = true;
        this.flagOutputDirty('working');

        UserManagement.instance.signUp(this._internal.username, this._internal.password, this._internal.attributes, {
          success: function () {
            _this._internal.working = false;
            _this.flagOutputDirty('working');

            _this.sendSignalOnOutput('success');
          },
          failure: function (err) {
            _this._internal.working = false;
            _this.flagOutputDirty('working');

            _this._internal.failureMessage = err;
            _this.flagOutputDirty('failureMessage');
            _this.sendSignalOnOutput('failure');
          }
        });
      }
    }
  },
  outputs: {
    success: {
      displayName: "Success",
      type: "signal",
      group: "Signals"
    },
    failure: {
      displayName: "Failure",
      type: "signal",
      group: "Signals"
    },
    failureMessage: {
      displayName: "Failure Message",
      type: "string",
      group: "Result",
      getter: function () {
        return this._internal.failureMessage;
      }
    },
    working: {
        displayName: "Working",
        type: "boolean",
        group: "Status",
        getter: function () {
          return this._internal.working;
        }
    }    
  },
  prototypeExtensions: {
  }
});

/* ---------------------------------------------------------------------------- 
   Verify User
   ---------------------------------------------------------------------------- */
Noodl.defineNode({
    name: "UserManagmenetVerifyUser",
    displayNodeName: "Verify User",
    category: "AWS IoT",
    initialize: function () {
        this._internal.working = false;
    },
    inputs: {
        username: {
            displayName: 'Username',
            group: 'User data',
            type: 'string',
            set: function (value) {
                this._internal.username = value;
            }
        },
        verificationCode: {
            displayName: 'Verification Code',
            group: 'User data',
            type: 'string',
            set: function (value) {
                this._internal.verificationCode = value;
            }
        },
        verifyUser: {
            displayName: 'Verify User',
            group: 'Actions',
            valueChangedToTrue: function () {
                var _this = this;

                this._internal.working = true;
                this.flagOutputDirty('working');

                UserManagement.instance.verifyUser(this._internal.username, this._internal.verificationCode, {
                    success: function () {
                        _this._internal.working = false;
                        _this.flagOutputDirty('working');

                        _this.sendSignalOnOutput('success');
                    },
                    failure: function (err) {
                        _this._internal.working = false;
                        _this.flagOutputDirty('working');

                        _this._internal.failureMessage = err;
                        _this.flagOutputDirty('failureMessage');
                        _this.sendSignalOnOutput('failure');
                    }
                });
            }
        },
        resendVerificationCode: {
            displayName: 'Resend Code',
            group: 'Actions',
            valueChangedToTrue: function () {
                var _this = this;

                this._internal.working = true;
                this.flagOutputDirty('working');

                UserManagement.instance.resendVerificationCode(this._internal.username, {
                    success: function () {
                        _this._internal.working = false;
                        _this.flagOutputDirty('working');

                        _this.sendSignalOnOutput('codeResendSuccess');
                    },
                    failure: function (err) {
                        _this._internal.working = false;
                        _this.flagOutputDirty('working');

                        _this._internal.failureMessage = err;
                        _this.flagOutputDirty('failureMessage');
                        _this.sendSignalOnOutput('failure');
                    }
                });
            }
        }
    },
    outputs: {
        success: {
            displayName: "Success",
            type: "signal",
            group: "Signals"
        },
        codeResendSuccess: {
            displayName: "Code Resent",
            type: "signal",
            group: "Signals"
        },
        failure: {
            displayName: "Failure",
            type: "signal",
            group: "Signals"
        },
        failureMessage: {
            displayName: "Failure Message",
            type: "string",
            group: "Result",
            getter: function () {
                return this._internal.failureMessage;
            }
        },
        working: {
            displayName: "Working",
            type: "boolean",
            group: "Status",
            getter: function () {
                return this._internal.working;
            }
        }          
    },
    prototypeExtensions: {
    }
});

/* ---------------------------------------------------------------------------- 
   Thing State
   ---------------------------------------------------------------------------- */
var modelPortsHash = {};

var ThingStateDefinition = {
    name: "Thing State",
    category: "AWS IoT",
    color: "data",           
    initialize: function() {
      var internal = this._internal;
      internal.inputValues = {};
      internal.stateValues = {};
    },
    outputs:{   
      stored:{
        type:'signal',
        displayName:'Stored',
        group:'Events',
      }       
    },
    inputs:{ 
      id:{
        type:'string',
        displayName:'Id',
        group:'General',
        set:function(value) {
          var _this = this;

          if(value == undefined || value === "") return;
          if(this._internal.thingId === value) return;
          if(this._internal.thingId)
            ThingState.instance.unregister(this._internal.thingId,this._internal.thingHandlers);

          this._internal.thingId = value;
          this._internal.thingHandlers = {
            onRegistered:function() {
              ThingState.instance.get(_this._internal.thingId,function(state) {
                _this._internal.stateValues = state;
                for(var i in state) {
                  if(_this.hasOutput(i))
                    _this.flagOutputDirty(i);
                }
              });
            },
            onDelta:function(state) {
              for(var i in state) {
                _this._internal.stateValues[i] = state[i];
                if(_this.hasOutput(i))
                    _this.flagOutputDirty(i);
              }
            }
          }
          ThingState.instance.register(this._internal.thingId,this._internal.thingHandlers);
        }
      },
      properties:{
        type:{name:'stringlist', allowEditOnly:true},
        displayName:'Properties',
        group:'Properties',
        set:function(value) {
        }
      },     
      store:{
        displayName:'Store',    
        group:'Actions',  
        valueChangedToTrue:function() {
          this.scheduleStore();
        }
      },
      clear:{
        displayName:'Clear',  
        group:'Actions',              
        valueChangedToTrue:function() {
        /*  var internal = this._internal;
          if(!internal.model) return;
          for(var i in internal.inputValues) {
            internal.model.set(i,undefined,{resolve:true});
          }*/
        }  
      }          
    },
    prototypeExtensions:{
      scheduleStore:function() {
        var _this = this;

        if(this.hasScheduledStore) return;
        this.hasScheduledStore = true;

        var internal = this._internal;
        this.scheduleAfterInputsHaveUpdated(function(){
          _this.sendSignalOnOutput('stored');
          _this.hasScheduledStore = false; 

          ThingState.instance.update(internal.thingId,internal.inputValues,function() {
           
          });

        });
      },
      _onNodeDeleted: function() {
        if(this._internal.thingId !== undefined && this._internal.thingId !== "")
          ThingState.instance.unregister(this._internal.thingId,this._internal.thingHandlers);
      },
      registerOutputIfNeeded: function(name) {
        if(this.hasOutput(name)) {
            return;
        }

        this.registerOutput(name, {
            getter: userOutputGetter.bind(this, name)
        });
      },
      registerInputIfNeeded: function(name) {
        var _this = this;
        
        if(this.hasInput(name)) {
            return;
        }
        
        this.registerInput(name, {
            set: userInputSetter.bind(this, name)
        });
      },               
    }
};

function userOutputGetter(name) {
    /* jshint validthis:true */
    return this._internal.stateValues[name];
    //return this._internal.model?this._internal.model.get(name,{resolve:true}):undefined;
}

function userInputSetter(name,value) {
  /* jshint validthis:true */
  this._internal.inputValues[name] = value;
  //this.scheduleStore();
}

function updatePorts(nodeId, properties, editorConnection) {
    var ports = [];

    // Add value outputs
    properties = properties ? properties.split(',') : undefined;
    for(var i in properties) {
        var p = properties[i];
        
        ports.push({
          type:{name:'*',
                allowConnectionsOnly:true},
          plug:'input/output',
          group:'Properties',
          name:p,
        });

    }

    var hash = JSON.stringify(ports);
    if(modelPortsHash[nodeId] !== hash) { // Make sure we don't resend the same port data
        modelPortsHash[nodeId] = hash;
        editorConnection.sendDynamicPorts(nodeId, ports);
    }
}

Noodl.defineNode({
    node: ThingStateDefinition,
    setup: function(context, graphModel) {

        if(!context.editorConnection || !context.editorConnection.isRunningLocally()) {
            return;
        }

        graphModel.on("nodeAdded.Thing State", function(node) {
            if(node.parameters.properties) {
                updatePorts(node.id, node.parameters.properties, context.editorConnection);
            }
            node.on("parameterUpdated", function(event) {
                if(event.name === "properties") {
                    updatePorts(node.id,  node.parameters.properties, context.editorConnection);
                }
            });
        });
    }
});

Noodl.projectSettings({
    ports:[
        {
            group: "AWS",
            type: "string",
            name: "awsIoTRegion",
            displayName: "Region",
            default: "us-east-1"
        }
    ]
})

Noodl.module(function() {
  console.log('Starting AWS-IOT module');

    setTimeout(function() {
        UserManagement.instance.attemptCachedSignIn();  
    },1);   
})
},{"./cloudfunctions":1,"./thingstate":3,"./usermanagement":4}],3:[function(require,module,exports){
/*
 * Copyright 2010-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

//node.js deps
var events = require('events');
var inherits = require('util').inherits;

//npm deps

//app deps
var deviceModule = {};

var isUndefined = function(value) {
   return typeof value === 'undefined' || typeof value === null;
};

//
// private functions
//
function buildThingShadowTopic(thingName, operation, type) {
   if (!isUndefined(type)) {
      return '$aws/things/' + thingName + '/shadow/' + operation + '/' + type;
   }
   return '$aws/things/' + thingName + '/shadow/' + operation;
}

function isReservedTopic(topic) {
   if (topic.substring(0, 12) === '$aws/things/') {
      return true;
   }
   return false;
}

function isThingShadowTopic(topicTokens, direction) {
   var rc = false;
   if (topicTokens[0] === '$aws') {
      //
      // Thing shadow topics have the form:
      //
      //      $aws/things/{thingName}/shadow/{Operation}/{Status}
      //
      // Where {Operation} === update|get|delete
      //   And    {Status} === accepted|rejected|delta
      //
      if ((topicTokens[1] === 'things') &&
         (topicTokens[3] === 'shadow') &&
         ((topicTokens[4] === 'update') ||
            (topicTokens[4] === 'get') ||
            (topicTokens[4] === 'delete'))) {
         //
         // Looks good so far; now check the direction and see if
         // still makes sense.
         //
         if (direction === 'subscribe') {
            if (((topicTokens[5] === 'accepted') ||
                  (topicTokens[5] === 'rejected') ||
                  (topicTokens[5] === 'delta')) &&
               (topicTokens.length === 6)) {
               rc = true;
            }
         } else // direction === 'publish'
         {
            if (topicTokens.length === 5) {
               rc = true;
            }
         }
      }
   }
   return rc;
}

//begin module

function ThingShadowsClient(deviceOptions, thingShadowOptions) {
   //
   // Force instantiation using the 'new' operator; this will cause inherited
   // constructors (e.g. the 'events' class) to be called.
   //
   if (!(this instanceof ThingShadowsClient)) {
      return new ThingShadowsClient(deviceOptions, thingShadowOptions);
   }

   //
   // A copy of 'this' for use inside of closures
   //
   var that = this;

   //
   // Track Thing Shadow registrations in here.
   //
   var thingShadows = [{}];

   //
   // Implements for every operation, used to construct clientToken.
   //
   var operationCount = 0;

   //
   // Operation timeout (milliseconds).  If no accepted or rejected response
   // to a thing operation is received within this time, subscriptions
   // to the accepted and rejected sub-topics for a thing are cancelled.
   //
   var operationTimeout = 10000; /* milliseconds */

   //
   // Variable used by the testing API setConnectionStatus() to simulate
   // network connectivity failures.
   //
   var connected = true;

   //
   // Instantiate the device.
   //
   var device = deviceModule.DeviceClient(deviceOptions);

   if (!isUndefined(thingShadowOptions)) {
      if (!isUndefined(thingShadowOptions.operationTimeout)) {
         operationTimeout = thingShadowOptions.operationTimeout;
      }
   }

   //
   // Private function to subscribe and unsubscribe from topics.
   //
   this._handleSubscriptions = function(thingName, topicSpecs, devFunction, callback) {
      var topics = [];

      //
      // Build an array of topic names.
      //
      for (var i = 0, topicsLen = topicSpecs.length; i < topicsLen; i++) {
         for (var j = 0, opsLen = topicSpecs[i].operations.length; j < opsLen; j++) {
            for (var k = 0, statLen = topicSpecs[i].statii.length; k < statLen; k++) {
               topics.push(buildThingShadowTopic(thingName,
                  topicSpecs[i].operations[j],
                  topicSpecs[i].statii[k]));
            }
         }
      }

      if (thingShadows[thingName].debug === true) {
         console.log(devFunction + ' on ' + topics);
      }
      //
      // Subscribe/unsubscribe from the topics and perform callback when complete.
      //
      var args = [];
      args.push(topics);
      if (devFunction === 'subscribe') {
         // QoS only applicable for subscribe
         args.push({
            qos: thingShadows[thingName].qos
         });
         // add our callback to check the SUBACK response for granted subscriptions
         args.push(function(err, granted) {
            if (!isUndefined(callback)) {
               if (err) {
                  callback(err);
                  return;
               }
               //
               // Check to see if we got all topic subscriptions granted.
               //
               var failedTopics = [];
               for (var k = 0, grantedLen = granted.length; k < grantedLen; k++) {
                  //
                  // 128 is 0x80 - Failure from the MQTT lib.
                  //
                  if (granted[k].qos === 128) {
                     failedTopics.push(granted[k]);
                  }
               }

               if (failedTopics.length > 0) {
                  callback('Not all subscriptions were granted', failedTopics);
                  return;
               }

               // all subscriptions were granted
               callback();
            }
         });
      } else {
         if (!isUndefined(callback)) {
            args.push(callback);
         }
      }

      device[devFunction].apply(device, args);
   };

   //
   // Private function to handle messages and dispatch them accordingly.
   //
   this._handleMessages = function(thingName, operation, operationStatus, payload) {
      var stateObject = {};
      try {
         stateObject = JSON.parse(payload.toString());
      } catch (err) {
         if (deviceOptions.debug === true) {
            console.error('failed parsing JSON \'' + payload.toString() + '\', ' + err);
         }
         return;
      }
      var clientToken = stateObject.clientToken;
      var version = stateObject.version;
      //
      // Remove the properties 'clientToken' and 'version' from the stateObject;
      // these properties are internal to this class.
      //
      delete stateObject.clientToken;
      delete stateObject.version;
      //
      // Update the thing version on every accepted or delta message which 
      // contains it.
      //
      if ((!isUndefined(version)) && (operationStatus !== 'rejected')) {
         //
         // The thing shadow version is incremented by AWS IoT and should always
         // increase.  Do not update our local version if the received version is
         // less than our version.  
         //
         if ((isUndefined(thingShadows[thingName].version)) ||
            (version >= thingShadows[thingName].version)) {
            thingShadows[thingName].version = version;
         } else {
            //
            // We've received a message from AWS IoT with a version number lower than
            // we would expect.  There are two things that can cause this:
            //
            //  1) The shadow has been deleted (version # reverts to 1 in this case.)
            //  2) The message has arrived out-of-order.
            //
            // For case 1) we can look at the operation to determine that this
            // is the case and notify the client if appropriate.  For case 2, 
            // we will not process it unless the client has specifically expressed
            // an interested in these messages by setting 'discardStale' to false.
            //
            if (operation !== 'delete' && thingShadows[thingName].discardStale === true) {
               if (deviceOptions.debug === true) {
                  console.warn('out-of-date version \'' + version + '\' on \'' +
                     thingName + '\' (local version \'' +
                     thingShadows[thingName].version + '\')');
               }
               return;
            }
         }
      }
      //
      // If this is a 'delta' message, emit an event for it and return.
      //
      if (operationStatus === 'delta') {
         this.emit('delta', thingName, stateObject);
         return;
      }
      //
      // only accepted/rejected messages past this point
      // ===============================================
      // If this is an unkown clientToken (e.g., it doesn't have a corresponding
      // client token property, the shadow has been modified by another client.
      // If it's an update/accepted or delete/accepted, update the shadow and
      // notify the client.
      //
      if (isUndefined(thingShadows[thingName].clientToken) ||
         thingShadows[thingName].clientToken !== clientToken) {
         if ((operationStatus === 'accepted') && (operation !== 'get')) {
            //
            // This is a foreign update or delete accepted, update our
            // shadow with the latest state and send a notification.
            //
            this.emit('foreignStateChange', thingName, operation, stateObject);
         }
         return;
      }
      //
      // A response has been received, so cancel any outstanding timeout on this
      // thingName/clientToken, delete the timeout handle, and unsubscribe from
      // all sub-topics.
      //
      clearTimeout(
         thingShadows[thingName].timeout);

      delete thingShadows[thingName].timeout;
      //
      // Delete the operation's client token.
      //
      delete thingShadows[thingName].clientToken;
      //
      // Mark this operation as complete.
      //
      thingShadows[thingName].pending = false;

      //
      // Unsubscribe from the 'accepted' and 'rejected' sub-topics unless we are
      // persistently subscribed to this thing shadow.
      //
      if (thingShadows[thingName].persistentSubscribe === false) {
         this._handleSubscriptions(thingName, [{
            operations: [operation],
            statii: ['accepted', 'rejected']
         }], 'unsubscribe');
      }

      //
      // Emit an event detailing the operation status; the clientToken is included
      // as an argument so that the application can correlate status events to
      // the operations they are associated with.
      //
      this.emit('status', thingName, operationStatus, clientToken, stateObject);
   };

   device.on('connect', function() {
      that.emit('connect');
   });
   device.on('close', function() {
      that.emit('close');
   });
   device.on('reconnect', function() {
      that.emit('reconnect');
   });
   device.on('offline', function() {
      that.emit('offline');
   });
   device.on('error', function(error) {
      that.emit('error', error);
   });
   device.on('message', function(topic, payload) {

      if (connected === true) {
         //
         // Parse the topic to determine what to do with it.
         //
         var topicTokens = topic.split('/');
         //
         // First, do a rough check to see if we should continue or not.
         //
         if (isThingShadowTopic(topicTokens, 'subscribe')) {
            //
            // This looks like a valid Thing topic, so see if the Thing is in the
            // registered Thing table.
            //
            if (thingShadows.hasOwnProperty(topicTokens[2])) {
               //
               // This is a registered Thing, so perform message handling on it.
               //
               that._handleMessages(topicTokens[2], // thingName
                  topicTokens[4], // operation
                  topicTokens[5], // status
                  payload);
            }
            //
            // Any messages received for unregistered Things fall here and are ignored.
            //
         } else {
            //
            // This isn't a Thing topic, so pass it along to the instance if they have
            // indicated they want to handle it.
            //
            that.emit('message', topic, payload);
         }
      }
   });

   this._thingOperation = function(thingName, operation, stateObject) {
      var rc = null;

      if (thingShadows.hasOwnProperty(thingName)) {
         //
         // Don't allow a new operation if an existing one is still in process.
         //
         if (thingShadows[thingName].pending === false) {
            //
            // Starting a new operation
            //
            thingShadows[thingName].pending = true;
            //
            // If not provided, construct a clientToken from the clientId and a rolling 
            // operation count.  The clientToken is transmitted in any published stateObject 
            // and is returned to the caller for each operation.  Applications can use
            // clientToken values to correlate received responses or timeouts with
            // the original operations.
            //
            var clientToken;

            if (isUndefined(stateObject.clientToken)) {
               //
               // AWS IoT restricts client tokens to 64 bytes, so use only the last 48
               // characters of the client ID when constructing a client token.
               //
               var clientIdLength = deviceOptions.clientId.length;

               if (clientIdLength > 48) {
                  clientToken = deviceOptions.clientId.substr(clientIdLength - 48) + '-' + operationCount++;
               } else {
                  clientToken = deviceOptions.clientId + '-' + operationCount++;
               }
            } else {
               clientToken = stateObject.clientToken;
            }
            //
            // Remember the client token for this operation; it will be
            // deleted when the operation completes or times out.
            //
            thingShadows[thingName].clientToken = clientToken;

            var publishTopic = buildThingShadowTopic(thingName,
               operation);
            //
            // Subscribe to the 'accepted' and 'rejected' sub-topics for this get
            // operation and set a timeout beyond which they will be unsubscribed if 
            // no messages have been received for either of them.
            //
            thingShadows[thingName].timeout = setTimeout(
               function(thingName, clientToken) {
                  //
                  // Timed-out.  Unsubscribe from the 'accepted' and 'rejected' sub-topics unless
                  // we are persistently subscribing to this thing shadow.
                  //
                  if (thingShadows[thingName].persistentSubscribe === false) {
                     that._handleSubscriptions(thingName, [{
                        operations: [operation],
                        statii: ['accepted', 'rejected']
                     }], 'unsubscribe');
                  }
                  //
                  // Mark this operation as complete.
                  //
                  thingShadows[thingName].pending = false;
                  //
                  // Emit an event for the timeout; the clientToken is included as an argument
                  // so that the application can correlate timeout events to the operations
                  // they are associated with.
                  //
                  that.emit('timeout', thingName, clientToken);
                  //
                  // Delete the timeout handle and client token for this thingName.
                  //
                  delete thingShadows[thingName].timeout;
                  delete thingShadows[thingName].clientToken;
               }, operationTimeout,
               thingName, clientToken);
            //
            // Subscribe to the 'accepted' and 'rejected' sub-topics unless we are
            // persistently subscribing, in which case we can publish to the topic immediately
            // since we are already subscribed to all applicable sub-topics.
            //
            if (thingShadows[thingName].persistentSubscribe === false) {
               this._handleSubscriptions(thingName, [{
                     operations: [operation],
                     statii: ['accepted', 'rejected'],
                  }], 'subscribe',
                  function(err, failedTopics) {
                     if (!isUndefined(err) || !isUndefined(failedTopics)) {
                        console.warn('failed subscription to accepted/rejected topics');
                        return;
                     }

                     //
                     // If 'stateObject' is defined, publish it to the publish topic for this
                     // thingName+operation.
                     //
                     if (!isUndefined(stateObject)) {
                        //
                        // Add the version # (if known and versioning is enabled) and 
                        // 'clientToken' properties to the stateObject.
                        //
                        if (!isUndefined(thingShadows[thingName].version) &&
                           thingShadows[thingName].enableVersioning) {
                           stateObject.version = thingShadows[thingName].version;
                        }
                        stateObject.clientToken = clientToken;

                        device.publish(publishTopic,
                           JSON.stringify(stateObject), {
                              qos: thingShadows[thingName].qos
                           });
                        if (!(isUndefined(thingShadows[thingName])) &&
                           thingShadows[thingName].debug === true) {
                           console.log('publishing \'' + JSON.stringify(stateObject) +
                              ' on \'' + publishTopic + '\'');
                        }
                     }
                  });
            } else {
               //
               // Add the version # (if known and versioning is enabled) and 
               // 'clientToken' properties to the stateObject.
               //
               if (!isUndefined(thingShadows[thingName].version) &&
                  thingShadows[thingName].enableVersioning) {
                  stateObject.version = thingShadows[thingName].version;
               }
               stateObject.clientToken = clientToken;

               device.publish(publishTopic,
                  JSON.stringify(stateObject), {
                     qos: thingShadows[thingName].qos
                  });
               if (thingShadows[thingName].debug === true) {
                  console.log('publishing \'' + JSON.stringify(stateObject) +
                     ' on \'' + publishTopic + '\'');
               }
            }
            rc = clientToken; // return the clientToken to the caller
         } else {
            if (deviceOptions.debug === true) {
               console.error(operation + ' still in progress on thing: ', thingName);
            }
         }
      } else {
         if (deviceOptions.debug === true) {
            console.error('attempting to ' + operation + ' unknown thing: ', thingName);
         }
      }
      return rc;
   };

   this.register = function(thingName, options, callback) {
      if (!thingShadows.hasOwnProperty(thingName)) {
         //
         // Initialize the registration entry for this thing; because the version # is 
         // not yet known, do not add the property for it yet. The version number 
         // property will be added after the first accepted update from AWS IoT.
         //
         var ignoreDeltas = false;
         var topicSpecs = [];
         thingShadows[thingName] = {
            persistentSubscribe: true,
            debug: false,
            discardStale: true,
            enableVersioning: true,
            qos: 0,
            pending: true
         };

         if (!isUndefined(options)) {
            if (!isUndefined(options.ignoreDeltas)) {
               ignoreDeltas = options.ignoreDeltas;
            }
            if (!isUndefined(options.persistentSubscribe)) {
               thingShadows[thingName].persistentSubscribe = options.persistentSubscribe;
            }
            if (!isUndefined(options.debug)) {
               thingShadows[thingName].debug = options.debug;
            }
            if (!isUndefined(options.discardStale)) {
               thingShadows[thingName].discardStale = options.discardStale;
            }
            if (!isUndefined(options.enableVersioning)) {
               thingShadows[thingName].enableVersioning = options.enableVersioning;
            }
            if (!isUndefined(options.qos)) {
               thingShadows[thingName].qos = options.qos;
            }
         }
         //
         // Always listen for deltas unless requested otherwise.
         //
         if (ignoreDeltas === false) {
            topicSpecs.push({
               operations: ['update'],
               statii: ['delta']
            });
         }
         //
         // If we are persistently subscribing, we subscribe to everything we could ever
         // possibly be interested in.  This will provide us the ability to publish
         // without waiting at the cost of potentially increased irrelevant traffic
         // which the application will need to filter out.
         //
         if (thingShadows[thingName].persistentSubscribe === true) {
            topicSpecs.push({
               operations: ['update', 'get', 'delete'],
               statii: ['accepted', 'rejected']
            });
         }

         if (topicSpecs.length > 0) {
            this._handleSubscriptions(thingName, topicSpecs, 'subscribe', function(err, failedTopics) {
               if (isUndefined(err) && isUndefined(failedTopics)) {
                  thingShadows[thingName].pending = false;
               }
               if (!isUndefined(callback)) {
                  callback(err, failedTopics);
               }
            });
         } else {
            thingShadows[thingName].pending = false;
            if (!isUndefined(callback)) {
               callback();
            }
         }

      } else {
         if (deviceOptions.debug === true) {
            console.error('thing already registered: ', thingName);
         }
      }
   };

   this.unregister = function(thingName) {
      if (thingShadows.hasOwnProperty(thingName)) {
         var topicSpecs = [];

         //
         // If an operation is outstanding, it will have a timeout set; when it
         // expires any accept/reject sub-topic subscriptions for the thing will be 
         // deleted.  If any messages arrive after the thing has been deleted, they
         // will simply be ignored as it no longer exists in the thing registrations.
         // The only sub-topic we need to unsubscribe from is the delta sub-topic,
         // which is always active.
         //
         topicSpecs.push({
            operations: ['update'],
            statii: ['delta']
         });
         //
         // If we are persistently subscribing, we subscribe to everything we could ever
         // possibly be interested in; this means that when it's time to unregister
         // interest in a thing, we need to unsubscribe from all of these topics.
         //
         if (thingShadows[thingName].persistentSubscribe === true) {
            topicSpecs.push({
               operations: ['update', 'get', 'delete'],
               statii: ['accepted', 'rejected']
            });
         }

         this._handleSubscriptions(thingName, topicSpecs, 'unsubscribe');

         //
         // Delete any pending timeout
         //
         if (!isUndefined(thingShadows[thingName].timeout)) {
            clearTimeout(thingShadows[thingName].timeout);
         }
         //
         // Delete the thing from the Thing registrations.
         //
         delete thingShadows[thingName];
      } else {
         if (deviceOptions.debug === true) {
            console.error('attempting to unregister unknown thing: ', thingName);
         }
      }
   };

   //
   // Perform an update operation on the given thing shadow.
   //
   this.update = function(thingName, stateObject) {
      var rc = null;
      //
      // Verify that the message does not contain a property named 'version',
      // as these property is reserved for use within this class.
      //
      if (isUndefined(stateObject.version)) {
         rc = that._thingOperation(thingName, 'update', stateObject);
      } else {
         console.error('message can\'t contain \'version\' property');
      }
      return rc;
   };

   //
   // Perform a get operation on the given thing shadow; allow the user
   // to specify their own client token if they don't want to use the
   // default.
   //
   this.get = function(thingName, clientToken) {
      var stateObject = {};
      if (!isUndefined(clientToken)) {
         stateObject.clientToken = clientToken;
      }
      return that._thingOperation(thingName, 'get', stateObject);
   };

   //
   // Perform a delete operation on the given thing shadow.
   //
   this.delete = function(thingName, clientToken) {
      var stateObject = {};
      if (!isUndefined(clientToken)) {
         stateObject.clientToken = clientToken;
      }
      return that._thingOperation(thingName, 'delete', stateObject);
   };
   //
   // Publish on non-thing topics.
   //
   this.publish = function(topic, message, options, callback) {
      if (!isReservedTopic(topic)) {
         device.publish(topic, message, options, callback);
      } else {
         throw ('cannot publish to reserved topic \'' + topic + '\'');
      }
   };

   //
   // Subscribe to non-thing topics.
   //
   this.subscribe = function(topic, options, callback) {
      if (!isReservedTopic(topic)) {
         device.subscribe(topic, options, callback);
      } else {
         throw ('cannot subscribe to reserved topic \'' + topic + '\'');
      }
   };
   //
   // Unsubscribe from non-thing topics.
   //
   this.unsubscribe = function(topic, callback) {
      if (!isReservedTopic(topic)) {
         device.unsubscribe(topic, callback);
      } else {
         throw ('cannot unsubscribe from reserved topic \'' + topic + '\'');
      }
   };
   //
   // Close the device connection; this will be passed through to
   // the device class.
   //
   this.end = function(force, callback) {
      device.end(force, callback);
   };
   //
   // Call this function to update the credentials used when
   // connecting via WebSocket/SigV4; this will be passed through
   // to the device class.
   //
   this.updateWebSocketCredentials = function(accessKeyId, secretKey, sessionToken, expiration) {
      device.updateWebSocketCredentials(accessKeyId, secretKey, sessionToken, expiration);
   };

   //
   // This is an unpublished API used for testing.
   //
   this.setConnectionStatus = function(connectionStatus) {
      connected = connectionStatus;
   };
   events.EventEmitter.call(this);
}

//
// Allow instances to listen in on events that we produce for them
//
inherits(ThingShadowsClient, events.EventEmitter);


var DeviceClient = function(options) {
   if (!(this instanceof DeviceClient)) {
      return new DeviceClient(options);
   }

   this.subscriptions = {};
   return this;
}
inherits(DeviceClient, events.EventEmitter);

DeviceClient.prototype.handleMessage = function(message) {
  this.emit('message',message.topic,JSON.stringify(message.payload));
}

DeviceClient.prototype.subscribe = function(topics,options,callback) {
  for(var i in topics) {
    var topic = topics[i];
    if(!this.subscriptions[topic]) {
      Noodl.PubSub.subscribe(topic,this.handleMessage.bind(this));
      
      if(!this.subscriptions[topic]) this.subscriptions[topic] = 0;
      this.subscriptions[topic]++;  
    }
  }
  callback(null,[]);
}

DeviceClient.prototype.unsubscribe = function(topics) {
  for(var i in topics) {
    var topic = topics[i];

    if(!this.subscriptions[topic]) continue;
    this.subscriptions[topic]--;
    if(this.subscriptions[topic] === 0) {
      Noodl.PubSub.unsubscribe(topic);
    }
  }
}

DeviceClient.prototype.publish = function(topic,message,options) {
  Noodl.PubSub.publish(topic,JSON.parse(message));
}

deviceModule.DeviceClient = DeviceClient;

var ThingState = function(clientId) {
  var _this = this;
  this.callbacks = [];
  this.handlers = {};

  this.client = new ThingShadowsClient({clientId:clientId},{});

  this.client.on('status',function(thingName, stat, clientToken, stateObject) {
   //             console.log('received '+stat+' on '+thingName+': '+
     //                       JSON.stringify(stateObject));

    var cb = _this.callbacks[clientToken];
    if(cb && stat === "accepted") {
      var desiredState = stateObject.state.desired;
      cb(desiredState);
      delete _this.callbacks[clientToken];
    }
  });

  this.client.on('delta',function(thingName, stateObject) {
    var handlers = _this.handlers[thingName];
    for(var i = 0; i < handlers.length; i++) {
      handlers[i].onDelta(stateObject.state);
    }
   //    console.log('received delta on '+thingName+': '+
     //              JSON.stringify(stateObject));
                   
  });
}

ThingState.prototype.register = function(name,handlers) {
  var _this = this;

  this.client.register(name,{},function() {
    if(!_this.handlers[name]) _this.handlers[name] = [];
    if(_this.handlers[name].indexOf(handlers) === -1)
      _this.handlers[name].push(handlers);

    handlers.onRegistered();
  });
}

ThingState.prototype.unregister = function(name,handlers) {
  if(!this.handlers[name]) return;
  var idx = this.handlers[name].indexOf(handlers) ;
  if(idx !== -1) {
    this.handlers[name].splice(idx,1);
  }
  if(this.handlers[name].length === 0) {
    this.client.unregister(name);
  }
}

ThingState.prototype.update = function(name,state) {
  var _state = {"state":{"desired":state}};
  this.client.update(name,_state);
}

ThingState.prototype.get = function(name,callback) {
  var clientToken = this.client.get(name);
  this.callbacks[clientToken] = callback;
}

ThingState.instance = new ThingState('wup');

module.exports = ThingState;
},{"events":5,"util":9}],4:[function(require,module,exports){
"use strict";

var EventEmitter = require('events').EventEmitter;

function UserManagement() {
    var _this = this;

    this.sessionState = UserManagement.SessionState.Invalid;
    this.events = new EventEmitter();
}

UserManagement.prototype.SessionState = UserManagement.SessionState = {
    Valid: 'Valid',
    Invalid: 'Invalid',
    Pending: 'Pending',
};

UserManagement.prototype.getSessionState = function() {
    return this.sessionState;
}

UserManagement.prototype.attemptCachedSignIn = function() {
    var _this = this;

    this.sessionState = UserManagement.SessionState.Pending;
    this.attemptSignInWithCachedTokens({
        failure:function() {
            _this.events.emit('userManagementCachedCredentialsNotAvailable');
        },
        success:function() { 
        }
    })     
}

/*
UserManagement.prototype.setSettings = function (settings) {
    var _this = this;

    this.settings = settings;
    this.sessionState = UserManagement.SessionState.Pending;
    this.attemptSignInWithCachedTokens({
        failure:function() {
            Services.events.emit('userManagementCachedCredentialsNotAvailable');
        },
        success:function() { 
        }
    })
}*/

UserManagement.prototype.getCredentials = function(token,args) {
    var _this = this;

    var settings = Noodl.getProjectSettings();

    AWS.config.region = Noodl.getProjectSettings().awsIoTRegion||'us-east-1';
    var creds = {
        IdentityPoolId: settings.userManagementAWSIdentityPoolId,
        Logins: {
        }
    };
    creds.Logins['cognito-idp.us-east-1.amazonaws.com/' + settings.userManagementAWSUserPoolId] = token;

    AWS.config.credentials = new AWS.CognitoIdentityCredentials(creds);

    AWS.config.credentials.get(function (err) {
        if (err) {
            _this.sessionState = UserManagement.SessionState.Invalid;
            args && args.failure && args.failure(err.message);
            return;
        }
        _this.sessionState = UserManagement.SessionState.Valid;
        _this.events.emit('userManagementCredentialsReceived'); 
        Noodl.PubSub.reconnect();       
        args && args.success && args.success();
    });    
}

UserManagement.prototype.attemptSignInWithCachedTokens = function (args) {
    var _this = this;

    var settings = Noodl.getProjectSettings();
    var poolData = {
        UserPoolId: settings.userManagementAWSUserPoolId, // your user pool id here
        ClientId: settings.userManagementAWSUserPoolClientAppId // your app client id here
    };
    var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
    var cognitoUser = userPool.getCurrentUser();

    if (cognitoUser != null) {
        cognitoUser.getSession(function (err, session) {
            if (err) {
                args&&args.failure&&args.failure(err.message);
                return;
            }

            if(!session.isValid()) {
                args&&args.failure&&args.failure("Session is not valid.");
                return;
            }

            _this.getCredentials(session.getIdToken().getJwtToken(),args);
        });
    }
    else {
        this.sessionState = UserManagement.SessionState.Invalid;        
        // Notify async, after app have been loaded
        setTimeout(function() {
            args&&args.failure&&args.failure("No user cached.");
        },1);
    }
}

UserManagement.prototype.verifyUser = function (username, verificationCode, args) {
    var _this = this;

    var settings = Noodl.getProjectSettings();
    var poolData = {
        UserPoolId: settings.userManagementAWSUserPoolId, // your user pool id here
        ClientId: settings.userManagementAWSUserPoolClientAppId // your app client id here
    };
    var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
    var userData = {
        Username: username, // your username here
        Pool: userPool
    };
    var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

    cognitoUser.confirmRegistration(verificationCode, false, function (err, result) {
        if (err) {
            args && args.failure && args.failure(err.message);
            return;
        }
        args && args.success && args.success();

        _this.attemptSignInWithCachedTokens({
            failure:function() {
                _this.events.emit('userManagementCachedCredentialsNotAvailable');
            },
            success:function() { 
            }
        });

    });
}

UserManagement.prototype.resendVerificationCode = function (username, args) {
    var settings = Noodl.getProjectSettings();
    var poolData = {
        UserPoolId: settings.userManagementAWSUserPoolId, // your user pool id here
        ClientId: settings.userManagementAWSUserPoolClientAppId // your app client id here
    };
    var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
    var userData = {
        Username: username, // your username here
        Pool: userPool
    };
    var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

    cognitoUser.resendConfirmationCode(function (err, result) {
        if (err) {
            args && args.failure && args.failure(err.message);
            return;
        }
        args && args.success && args.success();
    });
}

UserManagement.prototype.signUp = function (username, password, attributes, args) {
    var settings = Noodl.getProjectSettings();
    var poolData = {
        UserPoolId: settings.userManagementAWSUserPoolId, // your user pool id here
        ClientId: settings.userManagementAWSUserPoolClientAppId // your app client id here
    };
    var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

    var attributeList = [];

    for (var i in attributes) {
        var a = new AmazonCognitoIdentity.CognitoUserAttribute({ Name: i, Value: attributes[i] });
        attributeList.push(a);
    }

    var cognitoUser;
    userPool.signUp(username, password, attributeList, null, function (err, result) {
        if (err) {
            args && args.failure && args.failure(err.message);
            return;
        }

        args && args.success && args.success();
    });
}

UserManagement.prototype.signIn = function (username, password, args) {
    var _this = this;

    var settings = Noodl.getProjectSettings();
    var poolData = {
        UserPoolId: settings.userManagementAWSUserPoolId, // your user pool id here
        ClientId: settings.userManagementAWSUserPoolClientAppId // your app client id here
    };
    var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
    var userData = {
        Username: username, // your username here
        Pool: userPool,
        Paranoia : 7        
    };

    var authenticationData = {
        Username: username, // your username here
        Password: password, // your password here
    };
    var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);

    var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
    this.sessionState = UserManagement.SessionState.Pending;    
    
    cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: function (result) {
            _this.accessToken = result.getAccessToken();

            _this.getCredentials(result.getIdToken().getJwtToken(),args);
        },
        onFailure: function (err) {
            _this.sessionState = UserManagement.SessionState.Invalid;
            if (err.code === "UserNotConfirmedException") {
                args && args.userNotConfirmed && args.userNotConfirmed();
            }
            else {
                args && args.failure && args.failure(err.message);
            }
            //   alert(err);
        },
        newPasswordRequired: function () {
            _this.sessionState = UserManagement.SessionState.Invalid;
            args && args.newPasswordRequired && args.newPasswordRequired();
        },
/*        mfaRequired: function (codeDeliveryDetails) {
            args && args.mfaRequired && args.mfaRequired();
            //     var verificationCode = prompt('Please input verification code' ,'');
            //   cognitoUser.sendMFACode(verificationCode, this);
        }*/
    });    
}

UserManagement.prototype.signOut = function() {
    var _this = this;

    var settings = Noodl.getProjectSettings();
    var poolData = {
        UserPoolId: settings.userManagementAWSUserPoolId, // your user pool id here
        ClientId: settings.userManagementAWSUserPoolClientAppId // your app client id here
    };
    var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
    var cognitoUser = userPool.getCurrentUser();

    if (cognitoUser != null) {
        cognitoUser.signOut();
        AWS.config.credentials&&AWS.config.credentials.clearCachedId();
    } 

    this.sessionState = UserManagement.SessionState.Invalid;
    _this.events.emit('userManagementSignedOut');       
}

UserManagement.prototype.getUserId = function() {
    if(this.sessionState !== UserManagement.SessionState.Valid) return undefined;
    else return AWS.config.credentials.identityId;
}

UserManagement.instance = new UserManagement();

module.exports = UserManagement;
},{"events":5}],5:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

function EventEmitter() {
  this._events = this._events || {};
  this._maxListeners = this._maxListeners || undefined;
}
module.exports = EventEmitter;

// Backwards-compat with node 0.10.x
EventEmitter.EventEmitter = EventEmitter;

EventEmitter.prototype._events = undefined;
EventEmitter.prototype._maxListeners = undefined;

// By default EventEmitters will print a warning if more than 10 listeners are
// added to it. This is a useful default which helps finding memory leaks.
EventEmitter.defaultMaxListeners = 10;

// Obviously not all Emitters should be limited to 10. This function allows
// that to be increased. Set to zero for unlimited.
EventEmitter.prototype.setMaxListeners = function(n) {
  if (!isNumber(n) || n < 0 || isNaN(n))
    throw TypeError('n must be a positive number');
  this._maxListeners = n;
  return this;
};

EventEmitter.prototype.emit = function(type) {
  var er, handler, len, args, i, listeners;

  if (!this._events)
    this._events = {};

  // If there is no 'error' event listener then throw.
  if (type === 'error') {
    if (!this._events.error ||
        (isObject(this._events.error) && !this._events.error.length)) {
      er = arguments[1];
      if (er instanceof Error) {
        throw er; // Unhandled 'error' event
      }
      throw TypeError('Uncaught, unspecified "error" event.');
    }
  }

  handler = this._events[type];

  if (isUndefined(handler))
    return false;

  if (isFunction(handler)) {
    switch (arguments.length) {
      // fast cases
      case 1:
        handler.call(this);
        break;
      case 2:
        handler.call(this, arguments[1]);
        break;
      case 3:
        handler.call(this, arguments[1], arguments[2]);
        break;
      // slower
      default:
        args = Array.prototype.slice.call(arguments, 1);
        handler.apply(this, args);
    }
  } else if (isObject(handler)) {
    args = Array.prototype.slice.call(arguments, 1);
    listeners = handler.slice();
    len = listeners.length;
    for (i = 0; i < len; i++)
      listeners[i].apply(this, args);
  }

  return true;
};

EventEmitter.prototype.addListener = function(type, listener) {
  var m;

  if (!isFunction(listener))
    throw TypeError('listener must be a function');

  if (!this._events)
    this._events = {};

  // To avoid recursion in the case that type === "newListener"! Before
  // adding it to the listeners, first emit "newListener".
  if (this._events.newListener)
    this.emit('newListener', type,
              isFunction(listener.listener) ?
              listener.listener : listener);

  if (!this._events[type])
    // Optimize the case of one listener. Don't need the extra array object.
    this._events[type] = listener;
  else if (isObject(this._events[type]))
    // If we've already got an array, just append.
    this._events[type].push(listener);
  else
    // Adding the second element, need to change to array.
    this._events[type] = [this._events[type], listener];

  // Check for listener leak
  if (isObject(this._events[type]) && !this._events[type].warned) {
    if (!isUndefined(this._maxListeners)) {
      m = this._maxListeners;
    } else {
      m = EventEmitter.defaultMaxListeners;
    }

    if (m && m > 0 && this._events[type].length > m) {
      this._events[type].warned = true;
      console.error('(node) warning: possible EventEmitter memory ' +
                    'leak detected. %d listeners added. ' +
                    'Use emitter.setMaxListeners() to increase limit.',
                    this._events[type].length);
      if (typeof console.trace === 'function') {
        // not supported in IE 10
        console.trace();
      }
    }
  }

  return this;
};

EventEmitter.prototype.on = EventEmitter.prototype.addListener;

EventEmitter.prototype.once = function(type, listener) {
  if (!isFunction(listener))
    throw TypeError('listener must be a function');

  var fired = false;

  function g() {
    this.removeListener(type, g);

    if (!fired) {
      fired = true;
      listener.apply(this, arguments);
    }
  }

  g.listener = listener;
  this.on(type, g);

  return this;
};

// emits a 'removeListener' event iff the listener was removed
EventEmitter.prototype.removeListener = function(type, listener) {
  var list, position, length, i;

  if (!isFunction(listener))
    throw TypeError('listener must be a function');

  if (!this._events || !this._events[type])
    return this;

  list = this._events[type];
  length = list.length;
  position = -1;

  if (list === listener ||
      (isFunction(list.listener) && list.listener === listener)) {
    delete this._events[type];
    if (this._events.removeListener)
      this.emit('removeListener', type, listener);

  } else if (isObject(list)) {
    for (i = length; i-- > 0;) {
      if (list[i] === listener ||
          (list[i].listener && list[i].listener === listener)) {
        position = i;
        break;
      }
    }

    if (position < 0)
      return this;

    if (list.length === 1) {
      list.length = 0;
      delete this._events[type];
    } else {
      list.splice(position, 1);
    }

    if (this._events.removeListener)
      this.emit('removeListener', type, listener);
  }

  return this;
};

EventEmitter.prototype.removeAllListeners = function(type) {
  var key, listeners;

  if (!this._events)
    return this;

  // not listening for removeListener, no need to emit
  if (!this._events.removeListener) {
    if (arguments.length === 0)
      this._events = {};
    else if (this._events[type])
      delete this._events[type];
    return this;
  }

  // emit removeListener for all listeners on all events
  if (arguments.length === 0) {
    for (key in this._events) {
      if (key === 'removeListener') continue;
      this.removeAllListeners(key);
    }
    this.removeAllListeners('removeListener');
    this._events = {};
    return this;
  }

  listeners = this._events[type];

  if (isFunction(listeners)) {
    this.removeListener(type, listeners);
  } else if (listeners) {
    // LIFO order
    while (listeners.length)
      this.removeListener(type, listeners[listeners.length - 1]);
  }
  delete this._events[type];

  return this;
};

EventEmitter.prototype.listeners = function(type) {
  var ret;
  if (!this._events || !this._events[type])
    ret = [];
  else if (isFunction(this._events[type]))
    ret = [this._events[type]];
  else
    ret = this._events[type].slice();
  return ret;
};

EventEmitter.prototype.listenerCount = function(type) {
  if (this._events) {
    var evlistener = this._events[type];

    if (isFunction(evlistener))
      return 1;
    else if (evlistener)
      return evlistener.length;
  }
  return 0;
};

EventEmitter.listenerCount = function(emitter, type) {
  return emitter.listenerCount(type);
};

function isFunction(arg) {
  return typeof arg === 'function';
}

function isNumber(arg) {
  return typeof arg === 'number';
}

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}

function isUndefined(arg) {
  return arg === void 0;
}

},{}],6:[function(require,module,exports){
if (typeof Object.create === 'function') {
  // implementation from standard node.js 'util' module
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    ctor.prototype = Object.create(superCtor.prototype, {
      constructor: {
        value: ctor,
        enumerable: false,
        writable: true,
        configurable: true
      }
    });
  };
} else {
  // old school shim for old browsers
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    var TempCtor = function () {}
    TempCtor.prototype = superCtor.prototype
    ctor.prototype = new TempCtor()
    ctor.prototype.constructor = ctor
  }
}

},{}],7:[function(require,module,exports){
// shim for using process in browser

var process = module.exports = {};
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = setTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    clearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        setTimeout(drainQueue, 0);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],8:[function(require,module,exports){
module.exports = function isBuffer(arg) {
  return arg && typeof arg === 'object'
    && typeof arg.copy === 'function'
    && typeof arg.fill === 'function'
    && typeof arg.readUInt8 === 'function';
}
},{}],9:[function(require,module,exports){
(function (process,global){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var formatRegExp = /%[sdj%]/g;
exports.format = function(f) {
  if (!isString(f)) {
    var objects = [];
    for (var i = 0; i < arguments.length; i++) {
      objects.push(inspect(arguments[i]));
    }
    return objects.join(' ');
  }

  var i = 1;
  var args = arguments;
  var len = args.length;
  var str = String(f).replace(formatRegExp, function(x) {
    if (x === '%%') return '%';
    if (i >= len) return x;
    switch (x) {
      case '%s': return String(args[i++]);
      case '%d': return Number(args[i++]);
      case '%j':
        try {
          return JSON.stringify(args[i++]);
        } catch (_) {
          return '[Circular]';
        }
      default:
        return x;
    }
  });
  for (var x = args[i]; i < len; x = args[++i]) {
    if (isNull(x) || !isObject(x)) {
      str += ' ' + x;
    } else {
      str += ' ' + inspect(x);
    }
  }
  return str;
};


// Mark that a method should not be used.
// Returns a modified function which warns once by default.
// If --no-deprecation is set, then it is a no-op.
exports.deprecate = function(fn, msg) {
  // Allow for deprecating things in the process of starting up.
  if (isUndefined(global.process)) {
    return function() {
      return exports.deprecate(fn, msg).apply(this, arguments);
    };
  }

  if (process.noDeprecation === true) {
    return fn;
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (process.throwDeprecation) {
        throw new Error(msg);
      } else if (process.traceDeprecation) {
        console.trace(msg);
      } else {
        console.error(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
};


var debugs = {};
var debugEnviron;
exports.debuglog = function(set) {
  if (isUndefined(debugEnviron))
    debugEnviron = process.env.NODE_DEBUG || '';
  set = set.toUpperCase();
  if (!debugs[set]) {
    if (new RegExp('\\b' + set + '\\b', 'i').test(debugEnviron)) {
      var pid = process.pid;
      debugs[set] = function() {
        var msg = exports.format.apply(exports, arguments);
        console.error('%s %d: %s', set, pid, msg);
      };
    } else {
      debugs[set] = function() {};
    }
  }
  return debugs[set];
};


/**
 * Echos the value of a value. Trys to print the value out
 * in the best way possible given the different types.
 *
 * @param {Object} obj The object to print out.
 * @param {Object} opts Optional options object that alters the output.
 */
/* legacy: obj, showHidden, depth, colors*/
function inspect(obj, opts) {
  // default options
  var ctx = {
    seen: [],
    stylize: stylizeNoColor
  };
  // legacy...
  if (arguments.length >= 3) ctx.depth = arguments[2];
  if (arguments.length >= 4) ctx.colors = arguments[3];
  if (isBoolean(opts)) {
    // legacy...
    ctx.showHidden = opts;
  } else if (opts) {
    // got an "options" object
    exports._extend(ctx, opts);
  }
  // set default options
  if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
  if (isUndefined(ctx.depth)) ctx.depth = 2;
  if (isUndefined(ctx.colors)) ctx.colors = false;
  if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
  if (ctx.colors) ctx.stylize = stylizeWithColor;
  return formatValue(ctx, obj, ctx.depth);
}
exports.inspect = inspect;


// http://en.wikipedia.org/wiki/ANSI_escape_code#graphics
inspect.colors = {
  'bold' : [1, 22],
  'italic' : [3, 23],
  'underline' : [4, 24],
  'inverse' : [7, 27],
  'white' : [37, 39],
  'grey' : [90, 39],
  'black' : [30, 39],
  'blue' : [34, 39],
  'cyan' : [36, 39],
  'green' : [32, 39],
  'magenta' : [35, 39],
  'red' : [31, 39],
  'yellow' : [33, 39]
};

// Don't use 'blue' not visible on cmd.exe
inspect.styles = {
  'special': 'cyan',
  'number': 'yellow',
  'boolean': 'yellow',
  'undefined': 'grey',
  'null': 'bold',
  'string': 'green',
  'date': 'magenta',
  // "name": intentionally not styling
  'regexp': 'red'
};


function stylizeWithColor(str, styleType) {
  var style = inspect.styles[styleType];

  if (style) {
    return '\u001b[' + inspect.colors[style][0] + 'm' + str +
           '\u001b[' + inspect.colors[style][1] + 'm';
  } else {
    return str;
  }
}


function stylizeNoColor(str, styleType) {
  return str;
}


function arrayToHash(array) {
  var hash = {};

  array.forEach(function(val, idx) {
    hash[val] = true;
  });

  return hash;
}


function formatValue(ctx, value, recurseTimes) {
  // Provide a hook for user-specified inspect functions.
  // Check that value is an object with an inspect function on it
  if (ctx.customInspect &&
      value &&
      isFunction(value.inspect) &&
      // Filter out the util module, it's inspect function is special
      value.inspect !== exports.inspect &&
      // Also filter out any prototype objects using the circular check.
      !(value.constructor && value.constructor.prototype === value)) {
    var ret = value.inspect(recurseTimes, ctx);
    if (!isString(ret)) {
      ret = formatValue(ctx, ret, recurseTimes);
    }
    return ret;
  }

  // Primitive types cannot have properties
  var primitive = formatPrimitive(ctx, value);
  if (primitive) {
    return primitive;
  }

  // Look up the keys of the object.
  var keys = Object.keys(value);
  var visibleKeys = arrayToHash(keys);

  if (ctx.showHidden) {
    keys = Object.getOwnPropertyNames(value);
  }

  // IE doesn't make error fields non-enumerable
  // http://msdn.microsoft.com/en-us/library/ie/dww52sbt(v=vs.94).aspx
  if (isError(value)
      && (keys.indexOf('message') >= 0 || keys.indexOf('description') >= 0)) {
    return formatError(value);
  }

  // Some type of object without properties can be shortcutted.
  if (keys.length === 0) {
    if (isFunction(value)) {
      var name = value.name ? ': ' + value.name : '';
      return ctx.stylize('[Function' + name + ']', 'special');
    }
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    }
    if (isDate(value)) {
      return ctx.stylize(Date.prototype.toString.call(value), 'date');
    }
    if (isError(value)) {
      return formatError(value);
    }
  }

  var base = '', array = false, braces = ['{', '}'];

  // Make Array say that they are Array
  if (isArray(value)) {
    array = true;
    braces = ['[', ']'];
  }

  // Make functions say that they are functions
  if (isFunction(value)) {
    var n = value.name ? ': ' + value.name : '';
    base = ' [Function' + n + ']';
  }

  // Make RegExps say that they are RegExps
  if (isRegExp(value)) {
    base = ' ' + RegExp.prototype.toString.call(value);
  }

  // Make dates with properties first say the date
  if (isDate(value)) {
    base = ' ' + Date.prototype.toUTCString.call(value);
  }

  // Make error with message first say the error
  if (isError(value)) {
    base = ' ' + formatError(value);
  }

  if (keys.length === 0 && (!array || value.length == 0)) {
    return braces[0] + base + braces[1];
  }

  if (recurseTimes < 0) {
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    } else {
      return ctx.stylize('[Object]', 'special');
    }
  }

  ctx.seen.push(value);

  var output;
  if (array) {
    output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
  } else {
    output = keys.map(function(key) {
      return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
    });
  }

  ctx.seen.pop();

  return reduceToSingleString(output, base, braces);
}


function formatPrimitive(ctx, value) {
  if (isUndefined(value))
    return ctx.stylize('undefined', 'undefined');
  if (isString(value)) {
    var simple = '\'' + JSON.stringify(value).replace(/^"|"$/g, '')
                                             .replace(/'/g, "\\'")
                                             .replace(/\\"/g, '"') + '\'';
    return ctx.stylize(simple, 'string');
  }
  if (isNumber(value))
    return ctx.stylize('' + value, 'number');
  if (isBoolean(value))
    return ctx.stylize('' + value, 'boolean');
  // For some reason typeof null is "object", so special case here.
  if (isNull(value))
    return ctx.stylize('null', 'null');
}


function formatError(value) {
  return '[' + Error.prototype.toString.call(value) + ']';
}


function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
  var output = [];
  for (var i = 0, l = value.length; i < l; ++i) {
    if (hasOwnProperty(value, String(i))) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          String(i), true));
    } else {
      output.push('');
    }
  }
  keys.forEach(function(key) {
    if (!key.match(/^\d+$/)) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          key, true));
    }
  });
  return output;
}


function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
  var name, str, desc;
  desc = Object.getOwnPropertyDescriptor(value, key) || { value: value[key] };
  if (desc.get) {
    if (desc.set) {
      str = ctx.stylize('[Getter/Setter]', 'special');
    } else {
      str = ctx.stylize('[Getter]', 'special');
    }
  } else {
    if (desc.set) {
      str = ctx.stylize('[Setter]', 'special');
    }
  }
  if (!hasOwnProperty(visibleKeys, key)) {
    name = '[' + key + ']';
  }
  if (!str) {
    if (ctx.seen.indexOf(desc.value) < 0) {
      if (isNull(recurseTimes)) {
        str = formatValue(ctx, desc.value, null);
      } else {
        str = formatValue(ctx, desc.value, recurseTimes - 1);
      }
      if (str.indexOf('\n') > -1) {
        if (array) {
          str = str.split('\n').map(function(line) {
            return '  ' + line;
          }).join('\n').substr(2);
        } else {
          str = '\n' + str.split('\n').map(function(line) {
            return '   ' + line;
          }).join('\n');
        }
      }
    } else {
      str = ctx.stylize('[Circular]', 'special');
    }
  }
  if (isUndefined(name)) {
    if (array && key.match(/^\d+$/)) {
      return str;
    }
    name = JSON.stringify('' + key);
    if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
      name = name.substr(1, name.length - 2);
      name = ctx.stylize(name, 'name');
    } else {
      name = name.replace(/'/g, "\\'")
                 .replace(/\\"/g, '"')
                 .replace(/(^"|"$)/g, "'");
      name = ctx.stylize(name, 'string');
    }
  }

  return name + ': ' + str;
}


function reduceToSingleString(output, base, braces) {
  var numLinesEst = 0;
  var length = output.reduce(function(prev, cur) {
    numLinesEst++;
    if (cur.indexOf('\n') >= 0) numLinesEst++;
    return prev + cur.replace(/\u001b\[\d\d?m/g, '').length + 1;
  }, 0);

  if (length > 60) {
    return braces[0] +
           (base === '' ? '' : base + '\n ') +
           ' ' +
           output.join(',\n  ') +
           ' ' +
           braces[1];
  }

  return braces[0] + base + ' ' + output.join(', ') + ' ' + braces[1];
}


// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.
function isArray(ar) {
  return Array.isArray(ar);
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return isObject(re) && objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}
exports.isObject = isObject;

function isDate(d) {
  return isObject(d) && objectToString(d) === '[object Date]';
}
exports.isDate = isDate;

function isError(e) {
  return isObject(e) &&
      (objectToString(e) === '[object Error]' || e instanceof Error);
}
exports.isError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

exports.isBuffer = require('./support/isBuffer');

function objectToString(o) {
  return Object.prototype.toString.call(o);
}


function pad(n) {
  return n < 10 ? '0' + n.toString(10) : n.toString(10);
}


var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
              'Oct', 'Nov', 'Dec'];

// 26 Feb 16:19:34
function timestamp() {
  var d = new Date();
  var time = [pad(d.getHours()),
              pad(d.getMinutes()),
              pad(d.getSeconds())].join(':');
  return [d.getDate(), months[d.getMonth()], time].join(' ');
}


// log is just a thin wrapper to console.log that prepends a timestamp
exports.log = function() {
  console.log('%s - %s', timestamp(), exports.format.apply(exports, arguments));
};


/**
 * Inherit the prototype methods from one constructor into another.
 *
 * The Function.prototype.inherits from lang.js rewritten as a standalone
 * function (not on Function.prototype). NOTE: If this file is to be loaded
 * during bootstrapping this function needs to be rewritten using some native
 * functions as prototype setup using normal JavaScript does not work as
 * expected during bootstrapping (see mirror.js in r114903).
 *
 * @param {function} ctor Constructor function which needs to inherit the
 *     prototype.
 * @param {function} superCtor Constructor function to inherit prototype from.
 */
exports.inherits = require('inherits');

exports._extend = function(origin, add) {
  // Don't do anything if add isn't an object
  if (!add || !isObject(add)) return origin;

  var keys = Object.keys(add);
  var i = keys.length;
  while (i--) {
    origin[keys[i]] = add[keys[i]];
  }
  return origin;
};

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"./support/isBuffer":8,"_process":7,"inherits":6}]},{},[2])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uLy4uLy4uL3Vzci9sb2NhbC9saWIvbm9kZV9tb2R1bGVzL2Jyb3dzZXJpZnkvbm9kZV9tb2R1bGVzL2Jyb3dzZXItcGFjay9fcHJlbHVkZS5qcyIsImNsb3VkZnVuY3Rpb25zLmpzIiwibWFpbi5qcyIsInRoaW5nc3RhdGUuanMiLCJ1c2VybWFuYWdlbWVudC5qcyIsIi4uLy4uLy4uLy4uLy4uLy4uL3Vzci9sb2NhbC9saWIvbm9kZV9tb2R1bGVzL2Jyb3dzZXJpZnkvbm9kZV9tb2R1bGVzL2V2ZW50cy9ldmVudHMuanMiLCIuLi8uLi8uLi8uLi8uLi8uLi91c3IvbG9jYWwvbGliL25vZGVfbW9kdWxlcy9icm93c2VyaWZ5L25vZGVfbW9kdWxlcy9pbmhlcml0cy9pbmhlcml0c19icm93c2VyLmpzIiwiLi4vLi4vLi4vLi4vLi4vLi4vdXNyL2xvY2FsL2xpYi9ub2RlX21vZHVsZXMvYnJvd3NlcmlmeS9ub2RlX21vZHVsZXMvcHJvY2Vzcy9icm93c2VyLmpzIiwiLi4vLi4vLi4vLi4vLi4vLi4vdXNyL2xvY2FsL2xpYi9ub2RlX21vZHVsZXMvYnJvd3NlcmlmeS9ub2RlX21vZHVsZXMvdXRpbC9zdXBwb3J0L2lzQnVmZmVyQnJvd3Nlci5qcyIsIi4uLy4uLy4uLy4uLy4uLy4uL3Vzci9sb2NhbC9saWIvbm9kZV9tb2R1bGVzL2Jyb3dzZXJpZnkvbm9kZV9tb2R1bGVzL3V0aWwvdXRpbC5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTtBQ0FBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDekJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNuNEJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDdjJCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDaFJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDMVNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN2QkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUMzRkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7QUNMQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBIiwiZmlsZSI6ImdlbmVyYXRlZC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzQ29udGVudCI6WyIoZnVuY3Rpb24gZSh0LG4scil7ZnVuY3Rpb24gcyhvLHUpe2lmKCFuW29dKXtpZighdFtvXSl7dmFyIGE9dHlwZW9mIHJlcXVpcmU9PVwiZnVuY3Rpb25cIiYmcmVxdWlyZTtpZighdSYmYSlyZXR1cm4gYShvLCEwKTtpZihpKXJldHVybiBpKG8sITApO3ZhciBmPW5ldyBFcnJvcihcIkNhbm5vdCBmaW5kIG1vZHVsZSAnXCIrbytcIidcIik7dGhyb3cgZi5jb2RlPVwiTU9EVUxFX05PVF9GT1VORFwiLGZ9dmFyIGw9bltvXT17ZXhwb3J0czp7fX07dFtvXVswXS5jYWxsKGwuZXhwb3J0cyxmdW5jdGlvbihlKXt2YXIgbj10W29dWzFdW2VdO3JldHVybiBzKG4/bjplKX0sbCxsLmV4cG9ydHMsZSx0LG4scil9cmV0dXJuIG5bb10uZXhwb3J0c312YXIgaT10eXBlb2YgcmVxdWlyZT09XCJmdW5jdGlvblwiJiZyZXF1aXJlO2Zvcih2YXIgbz0wO288ci5sZW5ndGg7bysrKXMocltvXSk7cmV0dXJuIHN9KSIsIlwidXNlIHN0cmljdFwiO1xuXG5mdW5jdGlvbiBDbG91ZEZ1bmN0aW9ucygpIHsgIFxufVxuXG5DbG91ZEZ1bmN0aW9ucy5wcm90b3R5cGUuY2FsbCA9IGZ1bmN0aW9uKG5hbWUscGFyYW1zLGFyZ3MpIHtcbiAgdmFyIGxhbWJkYSA9IG5ldyBBV1MuTGFtYmRhKCk7XG4gIHZhciBwYXJhbXMgPSB7XG4gICAgRnVuY3Rpb25OYW1lOiBuYW1lLFxuICAgIEludm9jYXRpb25UeXBlOiAnUmVxdWVzdFJlc3BvbnNlJywgICAgXG4gICAgUGF5bG9hZDogSlNPTi5zdHJpbmdpZnkocGFyYW1zKVxuICB9O1xuICBsYW1iZGEuaW52b2tlKHBhcmFtcywgZnVuY3Rpb24oZXJyLCBkYXRhKSB7XG4gICAgaWYgKGVycikge1xuICAgICAgY29uc29sZS5sb2coJ0Nsb3VkIGZ1bmN0aW9uIGVycm9yOicsZXJyKTtcbiAgICAgIGFyZ3MmJmFyZ3MuZmFpbHVyZSYmYXJncy5mYWlsdXJlKGVyci5tZXNzYWdlKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgY29uc29sZS5sb2coJ0Nsb3VkIGZ1bmN0aW9uIHN1Y2Nlc3M6JyxkYXRhKTtcbiAgICBhcmdzJiZhcmdzLnN1Y2Nlc3MmJmFyZ3Muc3VjY2VzcyhKU09OLnBhcnNlKGRhdGEuUGF5bG9hZCkpO1xuICB9KTtcbn1cblxuQ2xvdWRGdW5jdGlvbnMuaW5zdGFuY2UgPSBuZXcgQ2xvdWRGdW5jdGlvbnMoKTtcblxubW9kdWxlLmV4cG9ydHMgPSBDbG91ZEZ1bmN0aW9uczsiLCJ2YXIgVXNlck1hbmFnZW1lbnQgPSByZXF1aXJlKCcuL3VzZXJtYW5hZ2VtZW50Jyk7XG52YXIgVGhpbmdTdGF0ZSA9IHJlcXVpcmUoJy4vdGhpbmdzdGF0ZScpO1xudmFyIENsb3VkRnVuY3Rpb25zID0gcmVxdWlyZSgnLi9jbG91ZGZ1bmN0aW9ucycpO1xuXG4vKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIFxuICAgQ3VzdG9tIGJyb2tlciB0byBjb25uZWN0IHRvIEFXUyBJb1QgZGV2aWNlIGdhdGV3YXlcbiAgIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi9cbmZ1bmN0aW9uIFNpZ1Y0VXRpbHMoKSB7IH1cblxuU2lnVjRVdGlscy5zaWduID0gZnVuY3Rpb24gKGtleSwgbXNnKSB7XG4gICAgdmFyIGhhc2ggPSBDcnlwdG9KUy5IbWFjU0hBMjU2KG1zZywga2V5KTtcbiAgICByZXR1cm4gaGFzaC50b1N0cmluZyhDcnlwdG9KUy5lbmMuSGV4KTtcbn07XG5cblNpZ1Y0VXRpbHMuc2hhMjU2ID0gZnVuY3Rpb24gKG1zZykge1xuICAgIHZhciBoYXNoID0gQ3J5cHRvSlMuU0hBMjU2KG1zZyk7XG4gICAgcmV0dXJuIGhhc2gudG9TdHJpbmcoQ3J5cHRvSlMuZW5jLkhleCk7XG59O1xuXG5TaWdWNFV0aWxzLmdldFNpZ25hdHVyZUtleSA9IGZ1bmN0aW9uIChrZXksIGRhdGVTdGFtcCwgcmVnaW9uTmFtZSwgc2VydmljZU5hbWUpIHtcbiAgICB2YXIga0RhdGUgPSBDcnlwdG9KUy5IbWFjU0hBMjU2KGRhdGVTdGFtcCwgJ0FXUzQnICsga2V5KTtcbiAgICB2YXIga1JlZ2lvbiA9IENyeXB0b0pTLkhtYWNTSEEyNTYocmVnaW9uTmFtZSwga0RhdGUpO1xuICAgIHZhciBrU2VydmljZSA9IENyeXB0b0pTLkhtYWNTSEEyNTYoc2VydmljZU5hbWUsIGtSZWdpb24pO1xuICAgIHZhciBrU2lnbmluZyA9IENyeXB0b0pTLkhtYWNTSEEyNTYoJ2F3czRfcmVxdWVzdCcsIGtTZXJ2aWNlKTtcbiAgICByZXR1cm4ga1NpZ25pbmc7XG59O1xuXG5TaWdWNFV0aWxzLmdldFNpZ25lZFVybCA9IGZ1bmN0aW9uIChwcm90b2NvbCwgaG9zdCwgdXJpLCBzZXJ2aWNlLCByZWdpb24sIGFjY2Vzc0tleSwgc2VjcmV0S2V5LCBzZXNzaW9uVG9rZW4pIHtcbiAgICB2YXIgdGltZSA9IG1vbWVudCgpLnV0YygpO1xuICAgIHZhciBkYXRlU3RhbXAgPSB0aW1lLmZvcm1hdCgnWVlZWU1NREQnKTtcbiAgICB2YXIgYW16ZGF0ZSA9IGRhdGVTdGFtcCArICdUJyArIHRpbWUuZm9ybWF0KCdISG1tc3MnKSArICdaJztcbiAgICB2YXIgYWxnb3JpdGhtID0gJ0FXUzQtSE1BQy1TSEEyNTYnO1xuICAgIHZhciBtZXRob2QgPSAnR0VUJztcblxuICAgIHZhciBjcmVkZW50aWFsU2NvcGUgPSBkYXRlU3RhbXAgKyAnLycgKyByZWdpb24gKyAnLycgKyBzZXJ2aWNlICsgJy8nICsgJ2F3czRfcmVxdWVzdCc7XG4gICAgdmFyIGNhbm9uaWNhbFF1ZXJ5c3RyaW5nID0gJ1gtQW16LUFsZ29yaXRobT1BV1M0LUhNQUMtU0hBMjU2JztcbiAgICBjYW5vbmljYWxRdWVyeXN0cmluZyArPSAnJlgtQW16LUNyZWRlbnRpYWw9JyArIGVuY29kZVVSSUNvbXBvbmVudChhY2Nlc3NLZXkgKyAnLycgKyBjcmVkZW50aWFsU2NvcGUpO1xuICAgIGNhbm9uaWNhbFF1ZXJ5c3RyaW5nICs9ICcmWC1BbXotRGF0ZT0nICsgYW16ZGF0ZTtcbiAgICBjYW5vbmljYWxRdWVyeXN0cmluZyArPSAnJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCc7XG5cbiAgICB2YXIgY2Fub25pY2FsSGVhZGVycyA9ICdob3N0OicgKyBob3N0ICsgJ1xcbic7XG4gICAgdmFyIHBheWxvYWRIYXNoID0gU2lnVjRVdGlscy5zaGEyNTYoJycpO1xuICAgIHZhciBjYW5vbmljYWxSZXF1ZXN0ID0gbWV0aG9kICsgJ1xcbicgKyB1cmkgKyAnXFxuJyArIGNhbm9uaWNhbFF1ZXJ5c3RyaW5nICsgJ1xcbicgKyBjYW5vbmljYWxIZWFkZXJzICsgJ1xcbmhvc3RcXG4nICsgcGF5bG9hZEhhc2g7XG5cblxuICAgIHZhciBzdHJpbmdUb1NpZ24gPSBhbGdvcml0aG0gKyAnXFxuJyArIGFtemRhdGUgKyAnXFxuJyArIGNyZWRlbnRpYWxTY29wZSArICdcXG4nICsgU2lnVjRVdGlscy5zaGEyNTYoY2Fub25pY2FsUmVxdWVzdCk7XG4gICAgdmFyIHNpZ25pbmdLZXkgPSBTaWdWNFV0aWxzLmdldFNpZ25hdHVyZUtleShzZWNyZXRLZXksIGRhdGVTdGFtcCwgcmVnaW9uLCBzZXJ2aWNlKTtcbiAgICB2YXIgc2lnbmF0dXJlID0gU2lnVjRVdGlscy5zaWduKHNpZ25pbmdLZXksIHN0cmluZ1RvU2lnbik7XG5cbiAgICBjYW5vbmljYWxRdWVyeXN0cmluZyArPSAnJlgtQW16LVNpZ25hdHVyZT0nICsgc2lnbmF0dXJlO1xuICAgIGlmIChzZXNzaW9uVG9rZW4pIHtcbiAgICAgICAgY2Fub25pY2FsUXVlcnlzdHJpbmcgKz0gJyZYLUFtei1TZWN1cml0eS1Ub2tlbj0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHNlc3Npb25Ub2tlbik7XG4gICAgfVxuXG4gICAgdmFyIHJlcXVlc3RVcmwgPSBwcm90b2NvbCArICc6Ly8nICsgaG9zdCArIHVyaSArICc/JyArIGNhbm9uaWNhbFF1ZXJ5c3RyaW5nO1xuICAgIHJldHVybiByZXF1ZXN0VXJsO1xufVxuXG5Ob29kbC5kZWZpbmVCcm9rZXIoe1xuICBpZDonYXdzaW90JyxcbiAgbmFtZTonQVdTIElvVCcsXG4gIHNldHRpbmdzOltcbiAgICB7IFxuICAgICAgICAgIGdyb3VwOiBcIk1RVFRcIixcbiAgICAgICAgICB0eXBlOiBcInN0cmluZ1wiLFxuICAgICAgICAgIG5hbWU6IFwibXF0dEFXU0lvVEVuZHBvaW50XCIsXG4gICAgICAgICAgZGlzcGxheU5hbWU6IFwiRW5kcG9pbnRcIlxuICAgICAgfSxcbiAgICAgIHtcbiAgICAgICAgICBncm91cDogXCJNUVRUXCIsXG4gICAgICAgICAgdHlwZTogXCJzdHJpbmdcIixcbiAgICAgICAgICBuYW1lOiBcIm1xdHRBV1NJb1RBY2Nlc3NLZXlcIixcbiAgICAgICAgICBkaXNwbGF5TmFtZTogXCJBY2Nlc3MgS2V5XCJcbiAgICAgIH0sXG4gICAgICB7XG4gICAgICAgICAgZ3JvdXA6IFwiTVFUVFwiLFxuICAgICAgICAgIHR5cGU6IFwic3RyaW5nXCIsXG4gICAgICAgICAgbmFtZTogXCJtcXR0QVdTSW9UU2VjcmV0S2V5XCIsXG4gICAgICAgICAgZGlzcGxheU5hbWU6IFwiU2VjcmV0IEtleVwiXG4gICAgICB9ICAgICBcbiAgXSxcbiAgdXJsOmZ1bmN0aW9uKG9wdGlvbnMpIHtcbiAgICB2YXIgc2VydmljZSA9ICdpb3RkZXZpY2VnYXRld2F5JztcbiAgICB2YXIgcmVnaW9uID0gb3B0aW9ucy5hd3NJb1RSZWdpb258fCd1cy1lYXN0LTEnO1xuICAgIHZhciBzZWNyZXRLZXkgPSBvcHRpb25zLm1xdHRBV1NJb1RTZWNyZXRLZXk7XG4gICAgdmFyIGFjY2Vzc0tleSA9IG9wdGlvbnMubXF0dEFXU0lvVEFjY2Vzc0tleTtcbiAgICB2YXIgc2Vzc2lvblRva2VuO1xuICAgIGlmIChBV1MgJiYgQVdTLmNvbmZpZy5jcmVkZW50aWFscykge1xuICAgICAgICBhY2Nlc3NLZXkgPSBBV1MuY29uZmlnLmNyZWRlbnRpYWxzLmFjY2Vzc0tleUlkO1xuICAgICAgICBzZWNyZXRLZXkgPSBBV1MuY29uZmlnLmNyZWRlbnRpYWxzLnNlY3JldEFjY2Vzc0tleTtcbiAgICAgICAgc2Vzc2lvblRva2VuID0gQVdTLmNvbmZpZy5jcmVkZW50aWFscy5zZXNzaW9uVG9rZW47XG4gICAgfVxuICAgIGlmIChhY2Nlc3NLZXkgPT09IHVuZGVmaW5lZCB8fCBzZWNyZXRLZXkgPT09IHVuZGVmaW5lZCkgcmV0dXJuO1xuICAgIGlmIChhY2Nlc3NLZXkgPT09IFwiXCIgfHwgc2VjcmV0S2V5ID09PSBcIlwiKSByZXR1cm47XG4gICAgdmFyIGNhbm9uaWNhbFVyaSA9ICcvbXF0dCc7XG4gICAgdmFyIGhvc3QgPSBvcHRpb25zLm1xdHRBV1NJb1RFbmRwb2ludDtcblxuICAgIHJldHVybiBTaWdWNFV0aWxzLmdldFNpZ25lZFVybCgnd3NzJywgaG9zdCwgY2Fub25pY2FsVXJpLFxuICAgICAgICBzZXJ2aWNlLCByZWdpb24sIGFjY2Vzc0tleSwgc2VjcmV0S2V5LCBzZXNzaW9uVG9rZW4pO1xuICB9LFxufSlcblxuLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBcbiAgIFNpZ24gSW4gVXNlclxuICAgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSAqL1xuTm9vZGwuZGVmaW5lTm9kZSh7XG4gICAgbmFtZTogXCJVc2VyTWFuYWdtZW5ldFNpZ25JblwiLFxuICAgIGRpc3BsYXlOb2RlTmFtZTogXCJTaWduIEluIFVzZXJcIixcbiAgICBjYXRlZ29yeTogXCJBV1MgSW9UXCIsXG4gICAgaW5pdGlhbGl6ZTogZnVuY3Rpb24gKCkge1xuICAgICAgICB0aGlzLl9pbnRlcm5hbC53b3JraW5nID0gZmFsc2U7XG4gICAgfSxcbiAgICBpbnB1dHM6IHtcbiAgICAgICAgdXNlcm5hbWU6IHtcbiAgICAgICAgICAgIGRpc3BsYXlOYW1lOiAnVXNlcm5hbWUnLFxuICAgICAgICAgICAgZ3JvdXA6ICdVc2VyIGRhdGEnLFxuICAgICAgICAgICAgdHlwZTogJ3N0cmluZycsXG4gICAgICAgICAgICBzZXQ6IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICAgICAgICAgIHRoaXMuX2ludGVybmFsLnVzZXJuYW1lID0gdmFsdWU7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIHBhc3N3b3JkOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogJ1Bhc3N3b3JkJyxcbiAgICAgICAgICAgIGdyb3VwOiAnVXNlciBkYXRhJyxcbiAgICAgICAgICAgIHR5cGU6ICdzdHJpbmcnLFxuICAgICAgICAgICAgc2V0OiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgICAgICAgICB0aGlzLl9pbnRlcm5hbC5wYXNzd29yZCA9IHZhbHVlO1xuICAgICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICBzaWduaW46IHtcbiAgICAgICAgICAgIGRpc3BsYXlOYW1lOiAnU2lnbiBJbicsXG4gICAgICAgICAgICBncm91cDogJ0FjdGlvbnMnLFxuICAgICAgICAgICAgdmFsdWVDaGFuZ2VkVG9UcnVlOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgdmFyIF90aGlzID0gdGhpcztcblxuICAgICAgICAgICAgICAgIHRoaXMuX2ludGVybmFsLndvcmtpbmcgPSB0cnVlO1xuICAgICAgICAgICAgICAgIHRoaXMuZmxhZ091dHB1dERpcnR5KCd3b3JraW5nJyk7XG5cbiAgICAgICAgICAgICAgICBVc2VyTWFuYWdlbWVudC5pbnN0YW5jZS5zaWduSW4odGhpcy5faW50ZXJuYWwudXNlcm5hbWUsIHRoaXMuX2ludGVybmFsLnBhc3N3b3JkLCB7XG4gICAgICAgICAgICAgICAgICAgIHN1Y2Nlc3M6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIF90aGlzLl9pbnRlcm5hbC53b3JraW5nID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5mbGFnT3V0cHV0RGlydHkoJ3dvcmtpbmcnKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuc2VuZFNpZ25hbE9uT3V0cHV0KCdzdWNjZXNzJyk7XG4gICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIHVzZXJOb3RDb25maXJtZWQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIF90aGlzLl9pbnRlcm5hbC53b3JraW5nID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5mbGFnT3V0cHV0RGlydHkoJ3dvcmtpbmcnKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuc2VuZFNpZ25hbE9uT3V0cHV0KCd1c2VyTm90Q29uZmlybWVkJyk7XG4gICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIG5ld1Bhc3N3b3JkUmVxdWlyZWQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIF90aGlzLl9pbnRlcm5hbC53b3JraW5nID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5mbGFnT3V0cHV0RGlydHkoJ3dvcmtpbmcnKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuc2VuZFNpZ25hbE9uT3V0cHV0KCduZXdQYXNzd29yZFJlcXVpcmVkJyk7XG4gICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIGZhaWx1cmU6IGZ1bmN0aW9uIChlcnIpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIF90aGlzLl9pbnRlcm5hbC53b3JraW5nID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5mbGFnT3V0cHV0RGlydHkoJ3dvcmtpbmcnKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFxuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuX2ludGVybmFsLmZhaWx1cmVNZXNzYWdlID0gZXJyO1xuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuZmxhZ091dHB1dERpcnR5KCdmYWlsdXJlTWVzc2FnZScpO1xuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuc2VuZFNpZ25hbE9uT3V0cHV0KCdmYWlsdXJlJyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0sXG4gICAgb3V0cHV0czoge1xuICAgICAgICBzdWNjZXNzOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogXCJTdWNjZXNzXCIsXG4gICAgICAgICAgICB0eXBlOiBcInNpZ25hbFwiLFxuICAgICAgICAgICAgZ3JvdXA6IFwiU2lnbmFsc1wiXG4gICAgICAgIH0sXG4gICAgICAgIHVzZXJOb3RDb25maXJtZWQ6IHtcbiAgICAgICAgICAgIGRpc3BsYXlOYW1lOiBcIlVzZXIgTm90IENvbmZpcm1lZFwiLFxuICAgICAgICAgICAgdHlwZTogXCJzaWduYWxcIixcbiAgICAgICAgICAgIGdyb3VwOiBcIlNpZ25hbHNcIlxuICAgICAgICB9LFxuICAgICAgICBuZXdQYXNzd29yZFJlcXVpcmVkOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogXCJOZXcgUGFzc3dvcmQgUmVxdWlyZWRcIixcbiAgICAgICAgICAgIHR5cGU6IFwic2lnbmFsXCIsXG4gICAgICAgICAgICBncm91cDogXCJTaWduYWxzXCJcbiAgICAgICAgfSxcbiAgICAgICAgZmFpbHVyZToge1xuICAgICAgICAgICAgZGlzcGxheU5hbWU6IFwiRmFpbHVyZVwiLFxuICAgICAgICAgICAgdHlwZTogXCJzaWduYWxcIixcbiAgICAgICAgICAgIGdyb3VwOiBcIlNpZ25hbHNcIlxuICAgICAgICB9LFxuICAgICAgICBmYWlsdXJlTWVzc2FnZToge1xuICAgICAgICAgICAgZGlzcGxheU5hbWU6IFwiRmFpbHVyZSBNZXNzYWdlXCIsXG4gICAgICAgICAgICB0eXBlOiBcInN0cmluZ1wiLFxuICAgICAgICAgICAgZ3JvdXA6IFwiUmVzdWx0XCIsXG4gICAgICAgICAgICBnZXR0ZXI6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gdGhpcy5faW50ZXJuYWwuZmFpbHVyZU1lc3NhZ2U7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIHdvcmtpbmc6IHtcbiAgICAgICAgICAgIGRpc3BsYXlOYW1lOiBcIldvcmtpbmdcIixcbiAgICAgICAgICAgIHR5cGU6IFwiYm9vbGVhblwiLFxuICAgICAgICAgICAgZ3JvdXA6IFwiU3RhdHVzXCIsXG4gICAgICAgICAgICBnZXR0ZXI6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gdGhpcy5faW50ZXJuYWwud29ya2luZztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0sXG4gICAgcHJvdG90eXBlRXh0ZW5zaW9uczoge1xuICAgIH0sXG4gICAgc2V0dGluZ3M6W1xuICAgICAgICB7XG4gICAgICAgICAgICBncm91cDpcIkFXUyBDb2duaXRvXCIsXG4gICAgICAgICAgICB0eXBlOlwic3RyaW5nXCIsXG4gICAgICAgICAgICBkaXNwbGF5TmFtZTpcIlVzZXIgUG9vbCBJZFwiLFxuICAgICAgICAgICAgbmFtZTpcInVzZXJNYW5hZ2VtZW50QVdTVXNlclBvb2xJZFwiLFxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgICBncm91cDpcIkFXUyBDb2duaXRvXCIsXG4gICAgICAgICAgICB0eXBlOlwic3RyaW5nXCIsXG4gICAgICAgICAgICBkaXNwbGF5TmFtZTpcIkNsaWVudCBBcHAgSWRcIixcbiAgICAgICAgICAgIG5hbWU6XCJ1c2VyTWFuYWdlbWVudEFXU1VzZXJQb29sQ2xpZW50QXBwSWRcIixcbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgICAgZ3JvdXA6XCJBV1MgQ29nbml0b1wiLFxuICAgICAgICAgICAgdHlwZTpcInN0cmluZ1wiLFxuICAgICAgICAgICAgZGlzcGxheU5hbWU6XCJJZGVudGl0eSBQb29sIElkXCIsXG4gICAgICAgICAgICBuYW1lOlwidXNlck1hbmFnZW1lbnRBV1NJZGVudGl0eVBvb2xJZFwiLFxuICAgICAgICB9LCAgICAgICAgICAgICAgICAgICAgICAgXG4gICAgXVxufSk7XG5cbi8qIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gXG4gICBVc2VyIHNlc3Npb25cbiAgIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi9cbk5vb2RsLmRlZmluZU5vZGUoe1xuICAgIG5hbWU6IFwiVXNlck1hbmFnbWVuZXRVc2VyU2Vzc2lvblwiLFxuICAgIGRpc3BsYXlOb2RlTmFtZTogXCJVc2VyIFNlc3Npb25cIixcbiAgICBjYXRlZ29yeTogXCJBV1MgSW9UXCIsXG4gICAgaW5pdGlhbGl6ZTogZnVuY3Rpb24oKSB7XG4gICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuXG4gICAgICBmdW5jdGlvbiBmbGFnU2Vzc2lvblN0YXRlRGlydHkoKSB7XG4gICAgICAgIF90aGlzLmZsYWdPdXRwdXREaXJ0eSgnc2Vzc2lvblN0YXRlJyk7ICAgICAgICBcbiAgICAgICAgX3RoaXMuZmxhZ091dHB1dERpcnR5KCdpc1ZhbGlkJyk7XG4gICAgICAgIF90aGlzLmZsYWdPdXRwdXREaXJ0eSgnaXNJbnZhbGlkJyk7XG4gICAgICAgIF90aGlzLmZsYWdPdXRwdXREaXJ0eSgnaXNQZW5kaW5nJyk7XG4gICAgICAgIF90aGlzLmZsYWdPdXRwdXREaXJ0eSgndXNlcklkJyk7XG4gICAgICB9XG5cbiAgICAgIFVzZXJNYW5hZ2VtZW50Lmluc3RhbmNlLmV2ZW50cy5vbigndXNlck1hbmFnZW1lbnRDcmVkZW50aWFsc1JlY2VpdmVkJyxmdW5jdGlvbigpIHtcbiAgICAgICAgZmxhZ1Nlc3Npb25TdGF0ZURpcnR5KCk7XG4gICAgICAgIF90aGlzLnNlbmRTaWduYWxPbk91dHB1dCgnc2lnbmVkSW4nKTtcbiAgICAgIH0pO1xuXG4gICAgICBVc2VyTWFuYWdlbWVudC5pbnN0YW5jZS5ldmVudHMub24oJ3VzZXJNYW5hZ2VtZW50Q2FjaGVkQ3JlZGVudGlhbHNOb3RBdmFpbGFibGUnLGZ1bmN0aW9uKCkge1xuICAgICAgICBmbGFnU2Vzc2lvblN0YXRlRGlydHkoKTtcbiAgICAgIH0pO1xuXG4gICAgICBVc2VyTWFuYWdlbWVudC5pbnN0YW5jZS5ldmVudHMub24oJ3VzZXJNYW5hZ2VtZW50U2lnbmVkT3V0JyxmdW5jdGlvbigpIHtcbiAgICAgICAgZmxhZ1Nlc3Npb25TdGF0ZURpcnR5KCk7XG4gICAgICAgIF90aGlzLnNlbmRTaWduYWxPbk91dHB1dCgnc2lnbmVkT3V0Jyk7XG4gICAgICB9KTtcblxuICAgICAgVXNlck1hbmFnZW1lbnQuaW5zdGFuY2UuZXZlbnRzLm9uKCd1c2VyTWFuYWdlbWVudFNlc3Npb25Mb3N0JyxmdW5jdGlvbigpIHtcbiAgICAgICAgZmxhZ1Nlc3Npb25TdGF0ZURpcnR5KCk7XG4gICAgICAgIF90aGlzLnNlbmRTaWduYWxPbk91dHB1dCgnc2Vzc2lvbkxvc3QnKTtcbiAgICAgIH0pOyAgXG4gICAgICAgICAgICAgICBcbiAgICB9LFxuICAgIGlucHV0czoge1xuICAgICAgICBzaWduT3V0OiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogJ1NpZ24gT3V0JyxcbiAgICAgICAgICAgIGdyb3VwOiAnQWN0aW9ucycsXG4gICAgICAgICAgICB2YWx1ZUNoYW5nZWRUb1RydWU6IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICBVc2VyTWFuYWdlbWVudC5pbnN0YW5jZS5zaWduT3V0KCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0gICAgICAgICAgICAgICAgICAgICAgICAgICBcbiAgICB9LFxuICAgIG91dHB1dHM6IHtcbiAgICAgICAgc2Vzc2lvbkxvc3Q6IHtcbiAgICAgICAgICAgIGRpc3BsYXlOYW1lOiBcIlNlc3Npb24gTG9zdFwiLFxuICAgICAgICAgICAgdHlwZTogXCJzaWduYWxcIixcbiAgICAgICAgICAgIGdyb3VwOiBcIlNpZ25hbHNcIlxuICAgICAgICB9LCAgICAgIFxuICAgICAgICBzaWduZWRPdXQ6IHtcbiAgICAgICAgICAgIGRpc3BsYXlOYW1lOiBcIlNpZ25lZCBPdXRcIixcbiAgICAgICAgICAgIHR5cGU6IFwic2lnbmFsXCIsXG4gICAgICAgICAgICBncm91cDogXCJTaWduYWxzXCJcbiAgICAgICAgfSxcbiAgICAgICAgaXNWYWxpZDoge1xuICAgICAgICAgICAgZGlzcGxheU5hbWU6IFwiSXMgdmFsaWRcIixcbiAgICAgICAgICAgIHR5cGU6IFwiYm9vbGVhblwiLFxuICAgICAgICAgICAgZ3JvdXA6IFwiU3RhdHVzXCIsXG4gICAgICAgICAgICBnZXR0ZXI6IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICByZXR1cm4gVXNlck1hbmFnZW1lbnQuaW5zdGFuY2UuZ2V0U2Vzc2lvblN0YXRlKCkgPT09IFVzZXJNYW5hZ2VtZW50LlNlc3Npb25TdGF0ZS5WYWxpZDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgaXNJbnZhbGlkOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogXCJJcyBJbnZhbGlkXCIsXG4gICAgICAgICAgICB0eXBlOiBcImJvb2xlYW5cIixcbiAgICAgICAgICAgIGdyb3VwOiBcIlN0YXR1c1wiLFxuICAgICAgICAgICAgZ2V0dGVyOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIFVzZXJNYW5hZ2VtZW50Lmluc3RhbmNlLmdldFNlc3Npb25TdGF0ZSgpID09PSBVc2VyTWFuYWdlbWVudC5TZXNzaW9uU3RhdGUuSW52YWxpZDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgaXNQZW5kaW5nOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogXCJJcyBQZW5kaW5nXCIsXG4gICAgICAgICAgICB0eXBlOiBcImJvb2xlYW5cIixcbiAgICAgICAgICAgIGdyb3VwOiBcIlN0YXR1c1wiLFxuICAgICAgICAgICAgZ2V0dGVyOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIFVzZXJNYW5hZ2VtZW50Lmluc3RhbmNlLmdldFNlc3Npb25TdGF0ZSgpID09PSBVc2VyTWFuYWdlbWVudC5TZXNzaW9uU3RhdGUuUGVuZGluZztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgc2Vzc2lvblN0YXRlOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogXCJTZXNzaW9uIFN0YXRlXCIsXG4gICAgICAgICAgICB0eXBlOiBcInN0cmluZ1wiLFxuICAgICAgICAgICAgZ3JvdXA6IFwiU3RhdHVzXCIsXG4gICAgICAgICAgICBnZXR0ZXI6IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICByZXR1cm4gVXNlck1hbmFnZW1lbnQuaW5zdGFuY2UuZ2V0U2Vzc2lvblN0YXRlKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0sICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXG4gICAgICAgIHNpZ25lZEluOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogXCJTaWduZWQgSW5cIixcbiAgICAgICAgICAgIHR5cGU6IFwic2lnbmFsXCIsXG4gICAgICAgICAgICBncm91cDogXCJTaWduYWxzXCJcbiAgICAgICAgfSxcbiAgICAgICAgdXNlcklkOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogXCJVc2VyIElkXCIsXG4gICAgICAgICAgICB0eXBlOiBcInN0cmluZ1wiLFxuICAgICAgICAgICAgZ3JvdXA6IFwiVXNlciBJbmZvXCIsXG4gICAgICAgICAgICBnZXR0ZXI6IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBVc2VyTWFuYWdlbWVudC5pbnN0YW5jZS5nZXRVc2VySWQoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSAgICAgICBcbiAgICB9LFxuICAgIHByb3RvdHlwZUV4dGVuc2lvbnM6IHtcbiAgICB9XG59KVxuXG4vKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIFxuICAgQ2xvdWQgZnVuY3Rpb24gKExhbWJkYSlcbiAgIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi9cbnZhciBDbG91ZEZ1bmN0aW9uID0ge1xuICAgIG5hbWU6IFwiQ2xvdWQgRnVuY3Rpb25cIixcbiAgICBjYXRlZ29yeTogXCJBV1MgSW9UXCIsXG4gICAgY29sb3I6IFwiamF2YXNjcmlwdFwiLCAgXG4gICAgdXNlUG9ydEFzTGFiZWw6IFwibmFtZVwiLCAgICAgIFxuICAgIGluaXRpYWxpemU6IGZ1bmN0aW9uKCkge1xuICAgIH0sXG4gICAgaW5wdXRzOiB7XG4gICAgICAgIG5hbWU6IHtcbiAgICAgICAgICAgIGRpc3BsYXlOYW1lOiAnTmFtZScsXG4gICAgICAgICAgICBncm91cDogJ0dlbmVyYWwnLFxuICAgICAgICAgICAgdHlwZTogJ3N0cmluZycsXG4gICAgICAgICAgICBzZXQ6IGZ1bmN0aW9uKHZhbHVlKSB7XG4gICAgICAgICAgICAgIHRoaXMuX2ludGVybmFsLm5hbWUgPSB2YWx1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgY2FsbFBheWxvYWQ6IHtcbiAgICAgICAgICAgIHR5cGU6e25hbWU6J3N0cmluZ2xpc3QnLGFsbG93RWRpdE9ubHk6dHJ1ZX0sXG4gICAgICAgICAgICBkaXNwbGF5TmFtZTonQ2FsbCBQYXlsb2FkJyxcbiAgICAgICAgICAgIGdyb3VwOlwiQ2FsbCBQYXlsb2FkXCIsXG4gICAgICAgICAgICBzZXQ6ZnVuY3Rpb24odmFsdWUpIHtcbiAgICAgICAgICAgICAgICB0aGlzLl9pbnRlcm5hbC5jYWxsUGF5bG9hZCA9IHZhbHVlLnNwbGl0KCcsJyk7ICAgICAgICAgICAgIFxuICAgICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICByZXNwb25zZVBheWxvYWQ6IHtcbiAgICAgICAgICAgIHR5cGU6e25hbWU6J3N0cmluZ2xpc3QnLGFsbG93RWRpdE9ubHk6dHJ1ZX0sXG4gICAgICAgICAgICBkaXNwbGF5TmFtZTonUmVzcG9uc2UgUGF5bG9hZCcsXG4gICAgICAgICAgICBncm91cDpcIlJlc3BvbnNlIFBheWxvYWRcIixcbiAgICAgICAgICAgIHNldDpmdW5jdGlvbih2YWx1ZSkge1xuICAgICAgICAgICAgICAgIHRoaXMuX2ludGVybmFsLnJlc3BvbnNlUGF5bG9hZCA9IHZhbHVlLnNwbGl0KCcsJyk7ICAgICAgICAgICAgIFxuICAgICAgICAgICAgfVxuICAgICAgICB9LCAgICAgICAgICAgICAgICAgICAgICAgICBcbiAgICAgICAgY2FsbDoge1xuICAgICAgICAgICAgZGlzcGxheU5hbWU6ICdDYWxsJyxcbiAgICAgICAgICAgIGdyb3VwOiAnQWN0aW9ucycsXG4gICAgICAgICAgICB2YWx1ZUNoYW5nZWRUb1RydWU6IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuXG4gICAgICAgICAgICAgIENsb3VkRnVuY3Rpb25zLmluc3RhbmNlLmNhbGwodGhpcy5faW50ZXJuYWwubmFtZSx7fSx7XG4gICAgICAgICAgICAgICAgc3VjY2VzczpmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAgIF90aGlzLnNlbmRTaWduYWxPbk91dHB1dCgnc3VjY2VzcycpO1xuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgZmFpbHVyZTpmdW5jdGlvbihlcnIpIHtcbiAgICAgICAgICAgICAgICAgIF90aGlzLl9pbnRlcm5hbC5mYWlsdXJlTWVzc2FnZSA9IGVycjtcbiAgICAgICAgICAgICAgICAgIF90aGlzLmZsYWdPdXRwdXREaXJ0eSgnZmFpbHVyZU1lc3NhZ2UnKTtcbiAgICAgICAgICAgICAgICAgIF90aGlzLnNlbmRTaWduYWxPbk91dHB1dCgnZmFpbHVyZScpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9LFxuICAgIG91dHB1dHM6IHtcbiAgICAgICAgc3VjY2Vzczoge1xuICAgICAgICAgICAgZGlzcGxheU5hbWU6IFwiU3VjY2Vzc1wiLFxuICAgICAgICAgICAgdHlwZTogXCJzaWduYWxcIixcbiAgICAgICAgICAgIGdyb3VwOiBcIlNpZ25hbHNcIlxuICAgICAgICB9LCAgICAgICAgICAgICAgIFxuICAgICAgICBmYWlsdXJlOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogXCJGYWlsdXJlXCIsXG4gICAgICAgICAgICB0eXBlOiBcInNpZ25hbFwiLFxuICAgICAgICAgICAgZ3JvdXA6IFwiU2lnbmFsc1wiXG4gICAgICAgIH0sXG4gICAgICAgIGZhaWx1cmVNZXNzYWdlOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogXCJGYWlsdXJlIE1lc3NhZ2VcIixcbiAgICAgICAgICAgIHR5cGU6IFwic3RyaW5nXCIsXG4gICAgICAgICAgICBncm91cDogXCJSZXN1bHRcIixcbiAgICAgICAgICAgIGdldHRlcjogZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgIHJldHVybiB0aGlzLl9pbnRlcm5hbC5mYWlsdXJlTWVzc2FnZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0sXG4gICAgcHJvdG90eXBlRXh0ZW5zaW9uczoge1xuICAgIH1cbn07XG5cbmZ1bmN0aW9uIHVwZGF0ZVBvcnRzKG5vZGVJZCwgcGFyYW1ldGVycywgZWRpdG9yQ29ubmVjdGlvbikge1xuXG4gICAgdmFyIGNhbGxQYXlsb2FkID0gcGFyYW1ldGVycy5jYWxsUGF5bG9hZDtcbiAgICB2YXIgcmVzcG9uc2VQYXlsb2FkID0gcGFyYW1ldGVycy5yZXNwb25zZVBheWxvYWQ7XG4gICAgXG4gICAgdmFyIHBvcnRzID0gW107XG5cbiAgICAvLyBBZGQgY2FsbCBwYXlsb2FkIGlucHV0c1xuICAgIGNhbGxQYXlsb2FkSXRlbXMgPSBjYWxsUGF5bG9hZCA/IGNhbGxQYXlsb2FkLnNwbGl0KCcsJykgOiBbXTtcbiAgICBmb3IodmFyIGkgaW4gY2FsbFBheWxvYWRJdGVtcykge1xuICAgICAgICB2YXIgcCA9IGNhbGxQYXlsb2FkSXRlbXNbaV07XG5cbiAgICAgICAgcG9ydHMucHVzaCh7XG4gICAgICAgICAgICB0eXBlOntuYW1lOicqJyxcbiAgICAgICAgICAgICAgICBhbGxvd0Nvbm5lY3Rpb25zT25seTp0cnVlfSxcbiAgICAgICAgICAgIHBsdWc6J2lucHV0JyxcbiAgICAgICAgICAgIGdyb3VwOidDYWxsIFBheWxvYWQnLFxuICAgICAgICAgICAgbmFtZTpwLFxuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvLyBBZGQgcmVzcG9uc2UgcGF5bG9hZCBvdXRwdXRzXG4gICAgcmVzcG9uc2VQYXlsb2FkSXRlbXMgPSByZXNwb25zZVBheWxvYWQgPyByZXNwb25zZVBheWxvYWQuc3BsaXQoJywnKSA6IFtdO1xuICAgIGZvcih2YXIgaSBpbiByZXNwb25zZVBheWxvYWRJdGVtcykge1xuICAgICAgICB2YXIgcCA9IHJlc3BvbnNlUGF5bG9hZEl0ZW1zW2ldO1xuXG4gICAgICAgIHBvcnRzLnB1c2goe1xuICAgICAgICAgICAgdHlwZTp7bmFtZTonKicsXG4gICAgICAgICAgICAgICAgYWxsb3dDb25uZWN0aW9uc09ubHk6dHJ1ZX0sXG4gICAgICAgICAgICBwbHVnOidvdXRwdXQnLFxuICAgICAgICAgICAgZ3JvdXA6J1Jlc3BvbnNlIFBheWxvYWQnLFxuICAgICAgICAgICAgbmFtZTpwLFxuICAgICAgICB9KTtcbiAgICB9ICAgIFxuXG4gICAgdmFyIGhhc2ggPSBKU09OLnN0cmluZ2lmeShwb3J0cyk7XG4gICAgaWYoc3RhdGVzUG9ydHNIYXNoW25vZGVJZF0gIT09IGhhc2gpIHsgLy8gTWFrZSBzdXJlIHdlIGRvbid0IHJlc2VuZCB0aGUgc2FtZSBwb3J0IGRhdGFcbiAgICAgICAgc3RhdGVzUG9ydHNIYXNoW25vZGVJZF0gPSBoYXNoO1xuICAgICAgICBlZGl0b3JDb25uZWN0aW9uLnNlbmREeW5hbWljUG9ydHMobm9kZUlkLCBwb3J0cyk7XG4gICAgfVxufVxuXG5Ob29kbC5kZWZpbmVOb2RlKHtcbiAgICBub2RlOiBDbG91ZEZ1bmN0aW9uLFxuICAgIHNldHVwOiBmdW5jdGlvbihjb250ZXh0LCBncmFwaE1vZGVsKSB7XG5cbiAgICAgICAgaWYoIWNvbnRleHQuZWRpdG9yQ29ubmVjdGlvbiB8fCAhY29udGV4dC5lZGl0b3JDb25uZWN0aW9uLmlzUnVubmluZ0xvY2FsbHkoKSkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgZ3JhcGhNb2RlbC5vbihcIm5vZGVBZGRlZC5DbG91ZCBGdW5jdGlvblwiLCBmdW5jdGlvbihub2RlKSB7XG4gICAgICAgICAgICBpZihub2RlLnBhcmFtZXRlcnMuY2FsbFBheWxvYWQgfHwgbm9kZS5wYXJhbWV0ZXJzLnJlc3Bvc2VQYXlsb2FkKSB7XG4gICAgICAgICAgICAgICAgdXBkYXRlUG9ydHMobm9kZS5pZCwgbm9kZS5wYXJhbWV0ZXJzLCBjb250ZXh0LmVkaXRvckNvbm5lY3Rpb24pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgbm9kZS5vbihcInBhcmFtZXRlclVwZGF0ZWRcIiwgZnVuY3Rpb24oZXZlbnQpIHtcbiAgICAgICAgICAgICAgICBpZihldmVudC5uYW1lID09PSBcImNhbGxQYXlsb2FkXCIgfHwgZXZlbnQubmFtZSA9PT0gXCJyZXNwb3NlUGF5bG9hZFwiKSB7XG4gICAgICAgICAgICAgICAgICAgIHVwZGF0ZVBvcnRzKG5vZGUuaWQsICBub2RlLnBhcmFtZXRlcnMsIGNvbnRleHQuZWRpdG9yQ29ubmVjdGlvbik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgIH0gICAgXG59KTtcblxuLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBcbiAgIENsb3VkIGZ1bmN0aW9uIChMYW1iZGEpXG4gICAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXG5Ob29kbC5kZWZpbmVOb2RlKHtcbiAgbmFtZTogXCJVc2VyTWFuYWdtZW5ldFNpZ25VcFwiLFxuICBkaXNwbGF5Tm9kZU5hbWU6IFwiU2lnbiBVcCBVc2VyXCIsXG4gIGNhdGVnb3J5OiBcIkFXUyBJb1RcIixcbiAgaW5pdGlhbGl6ZTogZnVuY3Rpb24gKCkge1xuICAgIHRoaXMuX2ludGVybmFsLmF0dHJpYnV0ZXMgPSB7fTtcblxuICAgIHRoaXMuX2ludGVybmFsLndvcmtpbmcgPSBmYWxzZTtcbiAgfSxcbiAgaW5wdXRzOiB7XG4gICAgdXNlcm5hbWU6IHtcbiAgICAgIGRpc3BsYXlOYW1lOiAnVXNlcm5hbWUnLFxuICAgICAgZ3JvdXA6ICdVc2VyIGRhdGEnLFxuICAgICAgdHlwZTogJ3N0cmluZycsXG4gICAgICBzZXQ6IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICB0aGlzLl9pbnRlcm5hbC51c2VybmFtZSA9IHZhbHVlO1xuICAgICAgfVxuICAgIH0sXG4gICAgcGFzc3dvcmQ6IHtcbiAgICAgIGRpc3BsYXlOYW1lOiAnUGFzc3dvcmQnLFxuICAgICAgZ3JvdXA6ICdVc2VyIGRhdGEnLFxuICAgICAgdHlwZTogJ3N0cmluZycsXG4gICAgICBzZXQ6IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICB0aGlzLl9pbnRlcm5hbC5wYXNzd29yZCA9IHZhbHVlO1xuICAgICAgfVxuICAgIH0sXG4gICAgZW1haWw6IHtcbiAgICAgIGRpc3BsYXlOYW1lOiAnRW1haWwnLFxuICAgICAgZ3JvdXA6ICdVc2VyIGRhdGEnLFxuICAgICAgdHlwZTogJ3N0cmluZycsXG4gICAgICBzZXQ6IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICB0aGlzLl9pbnRlcm5hbC5hdHRyaWJ1dGVzWydlbWFpbCddID0gdmFsdWU7XG4gICAgICB9XG4gICAgfSxcbiAgICBzaWduVXA6IHtcbiAgICAgIGRpc3BsYXlOYW1lOiAnU2lnbiBVcCcsXG4gICAgICBncm91cDogJ0FjdGlvbnMnLFxuICAgICAgdmFsdWVDaGFuZ2VkVG9UcnVlOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG5cbiAgICAgICAgdGhpcy5faW50ZXJuYWwud29ya2luZyA9IHRydWU7XG4gICAgICAgIHRoaXMuZmxhZ091dHB1dERpcnR5KCd3b3JraW5nJyk7XG5cbiAgICAgICAgVXNlck1hbmFnZW1lbnQuaW5zdGFuY2Uuc2lnblVwKHRoaXMuX2ludGVybmFsLnVzZXJuYW1lLCB0aGlzLl9pbnRlcm5hbC5wYXNzd29yZCwgdGhpcy5faW50ZXJuYWwuYXR0cmlidXRlcywge1xuICAgICAgICAgIHN1Y2Nlc3M6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIF90aGlzLl9pbnRlcm5hbC53b3JraW5nID0gZmFsc2U7XG4gICAgICAgICAgICBfdGhpcy5mbGFnT3V0cHV0RGlydHkoJ3dvcmtpbmcnKTtcblxuICAgICAgICAgICAgX3RoaXMuc2VuZFNpZ25hbE9uT3V0cHV0KCdzdWNjZXNzJyk7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBmYWlsdXJlOiBmdW5jdGlvbiAoZXJyKSB7XG4gICAgICAgICAgICBfdGhpcy5faW50ZXJuYWwud29ya2luZyA9IGZhbHNlO1xuICAgICAgICAgICAgX3RoaXMuZmxhZ091dHB1dERpcnR5KCd3b3JraW5nJyk7XG5cbiAgICAgICAgICAgIF90aGlzLl9pbnRlcm5hbC5mYWlsdXJlTWVzc2FnZSA9IGVycjtcbiAgICAgICAgICAgIF90aGlzLmZsYWdPdXRwdXREaXJ0eSgnZmFpbHVyZU1lc3NhZ2UnKTtcbiAgICAgICAgICAgIF90aGlzLnNlbmRTaWduYWxPbk91dHB1dCgnZmFpbHVyZScpO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgfVxuICB9LFxuICBvdXRwdXRzOiB7XG4gICAgc3VjY2Vzczoge1xuICAgICAgZGlzcGxheU5hbWU6IFwiU3VjY2Vzc1wiLFxuICAgICAgdHlwZTogXCJzaWduYWxcIixcbiAgICAgIGdyb3VwOiBcIlNpZ25hbHNcIlxuICAgIH0sXG4gICAgZmFpbHVyZToge1xuICAgICAgZGlzcGxheU5hbWU6IFwiRmFpbHVyZVwiLFxuICAgICAgdHlwZTogXCJzaWduYWxcIixcbiAgICAgIGdyb3VwOiBcIlNpZ25hbHNcIlxuICAgIH0sXG4gICAgZmFpbHVyZU1lc3NhZ2U6IHtcbiAgICAgIGRpc3BsYXlOYW1lOiBcIkZhaWx1cmUgTWVzc2FnZVwiLFxuICAgICAgdHlwZTogXCJzdHJpbmdcIixcbiAgICAgIGdyb3VwOiBcIlJlc3VsdFwiLFxuICAgICAgZ2V0dGVyOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiB0aGlzLl9pbnRlcm5hbC5mYWlsdXJlTWVzc2FnZTtcbiAgICAgIH1cbiAgICB9LFxuICAgIHdvcmtpbmc6IHtcbiAgICAgICAgZGlzcGxheU5hbWU6IFwiV29ya2luZ1wiLFxuICAgICAgICB0eXBlOiBcImJvb2xlYW5cIixcbiAgICAgICAgZ3JvdXA6IFwiU3RhdHVzXCIsXG4gICAgICAgIGdldHRlcjogZnVuY3Rpb24gKCkge1xuICAgICAgICAgIHJldHVybiB0aGlzLl9pbnRlcm5hbC53b3JraW5nO1xuICAgICAgICB9XG4gICAgfSAgICBcbiAgfSxcbiAgcHJvdG90eXBlRXh0ZW5zaW9uczoge1xuICB9XG59KTtcblxuLyogLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBcbiAgIFZlcmlmeSBVc2VyXG4gICAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tICovXG5Ob29kbC5kZWZpbmVOb2RlKHtcbiAgICBuYW1lOiBcIlVzZXJNYW5hZ21lbmV0VmVyaWZ5VXNlclwiLFxuICAgIGRpc3BsYXlOb2RlTmFtZTogXCJWZXJpZnkgVXNlclwiLFxuICAgIGNhdGVnb3J5OiBcIkFXUyBJb1RcIixcbiAgICBpbml0aWFsaXplOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHRoaXMuX2ludGVybmFsLndvcmtpbmcgPSBmYWxzZTtcbiAgICB9LFxuICAgIGlucHV0czoge1xuICAgICAgICB1c2VybmFtZToge1xuICAgICAgICAgICAgZGlzcGxheU5hbWU6ICdVc2VybmFtZScsXG4gICAgICAgICAgICBncm91cDogJ1VzZXIgZGF0YScsXG4gICAgICAgICAgICB0eXBlOiAnc3RyaW5nJyxcbiAgICAgICAgICAgIHNldDogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgICAgICAgICAgdGhpcy5faW50ZXJuYWwudXNlcm5hbWUgPSB2YWx1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgdmVyaWZpY2F0aW9uQ29kZToge1xuICAgICAgICAgICAgZGlzcGxheU5hbWU6ICdWZXJpZmljYXRpb24gQ29kZScsXG4gICAgICAgICAgICBncm91cDogJ1VzZXIgZGF0YScsXG4gICAgICAgICAgICB0eXBlOiAnc3RyaW5nJyxcbiAgICAgICAgICAgIHNldDogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgICAgICAgICAgdGhpcy5faW50ZXJuYWwudmVyaWZpY2F0aW9uQ29kZSA9IHZhbHVlO1xuICAgICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICB2ZXJpZnlVc2VyOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogJ1ZlcmlmeSBVc2VyJyxcbiAgICAgICAgICAgIGdyb3VwOiAnQWN0aW9ucycsXG4gICAgICAgICAgICB2YWx1ZUNoYW5nZWRUb1RydWU6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuXG4gICAgICAgICAgICAgICAgdGhpcy5faW50ZXJuYWwud29ya2luZyA9IHRydWU7XG4gICAgICAgICAgICAgICAgdGhpcy5mbGFnT3V0cHV0RGlydHkoJ3dvcmtpbmcnKTtcblxuICAgICAgICAgICAgICAgIFVzZXJNYW5hZ2VtZW50Lmluc3RhbmNlLnZlcmlmeVVzZXIodGhpcy5faW50ZXJuYWwudXNlcm5hbWUsIHRoaXMuX2ludGVybmFsLnZlcmlmaWNhdGlvbkNvZGUsIHtcbiAgICAgICAgICAgICAgICAgICAgc3VjY2VzczogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuX2ludGVybmFsLndvcmtpbmcgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgIF90aGlzLmZsYWdPdXRwdXREaXJ0eSgnd29ya2luZycpO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5zZW5kU2lnbmFsT25PdXRwdXQoJ3N1Y2Nlc3MnKTtcbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgZmFpbHVyZTogZnVuY3Rpb24gKGVycikge1xuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuX2ludGVybmFsLndvcmtpbmcgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgIF90aGlzLmZsYWdPdXRwdXREaXJ0eSgnd29ya2luZycpO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5faW50ZXJuYWwuZmFpbHVyZU1lc3NhZ2UgPSBlcnI7XG4gICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5mbGFnT3V0cHV0RGlydHkoJ2ZhaWx1cmVNZXNzYWdlJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5zZW5kU2lnbmFsT25PdXRwdXQoJ2ZhaWx1cmUnKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9LFxuICAgICAgICByZXNlbmRWZXJpZmljYXRpb25Db2RlOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogJ1Jlc2VuZCBDb2RlJyxcbiAgICAgICAgICAgIGdyb3VwOiAnQWN0aW9ucycsXG4gICAgICAgICAgICB2YWx1ZUNoYW5nZWRUb1RydWU6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuXG4gICAgICAgICAgICAgICAgdGhpcy5faW50ZXJuYWwud29ya2luZyA9IHRydWU7XG4gICAgICAgICAgICAgICAgdGhpcy5mbGFnT3V0cHV0RGlydHkoJ3dvcmtpbmcnKTtcblxuICAgICAgICAgICAgICAgIFVzZXJNYW5hZ2VtZW50Lmluc3RhbmNlLnJlc2VuZFZlcmlmaWNhdGlvbkNvZGUodGhpcy5faW50ZXJuYWwudXNlcm5hbWUsIHtcbiAgICAgICAgICAgICAgICAgICAgc3VjY2VzczogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuX2ludGVybmFsLndvcmtpbmcgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgICAgIF90aGlzLmZsYWdPdXRwdXREaXJ0eSgnd29ya2luZycpO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5zZW5kU2lnbmFsT25PdXRwdXQoJ2NvZGVSZXNlbmRTdWNjZXNzJyk7XG4gICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIGZhaWx1cmU6IGZ1bmN0aW9uIChlcnIpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIF90aGlzLl9pbnRlcm5hbC53b3JraW5nID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAgICAgICBfdGhpcy5mbGFnT3V0cHV0RGlydHkoJ3dvcmtpbmcnKTtcblxuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuX2ludGVybmFsLmZhaWx1cmVNZXNzYWdlID0gZXJyO1xuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuZmxhZ091dHB1dERpcnR5KCdmYWlsdXJlTWVzc2FnZScpO1xuICAgICAgICAgICAgICAgICAgICAgICAgX3RoaXMuc2VuZFNpZ25hbE9uT3V0cHV0KCdmYWlsdXJlJyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0sXG4gICAgb3V0cHV0czoge1xuICAgICAgICBzdWNjZXNzOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogXCJTdWNjZXNzXCIsXG4gICAgICAgICAgICB0eXBlOiBcInNpZ25hbFwiLFxuICAgICAgICAgICAgZ3JvdXA6IFwiU2lnbmFsc1wiXG4gICAgICAgIH0sXG4gICAgICAgIGNvZGVSZXNlbmRTdWNjZXNzOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogXCJDb2RlIFJlc2VudFwiLFxuICAgICAgICAgICAgdHlwZTogXCJzaWduYWxcIixcbiAgICAgICAgICAgIGdyb3VwOiBcIlNpZ25hbHNcIlxuICAgICAgICB9LFxuICAgICAgICBmYWlsdXJlOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogXCJGYWlsdXJlXCIsXG4gICAgICAgICAgICB0eXBlOiBcInNpZ25hbFwiLFxuICAgICAgICAgICAgZ3JvdXA6IFwiU2lnbmFsc1wiXG4gICAgICAgIH0sXG4gICAgICAgIGZhaWx1cmVNZXNzYWdlOiB7XG4gICAgICAgICAgICBkaXNwbGF5TmFtZTogXCJGYWlsdXJlIE1lc3NhZ2VcIixcbiAgICAgICAgICAgIHR5cGU6IFwic3RyaW5nXCIsXG4gICAgICAgICAgICBncm91cDogXCJSZXN1bHRcIixcbiAgICAgICAgICAgIGdldHRlcjogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLl9pbnRlcm5hbC5mYWlsdXJlTWVzc2FnZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSxcbiAgICAgICAgd29ya2luZzoge1xuICAgICAgICAgICAgZGlzcGxheU5hbWU6IFwiV29ya2luZ1wiLFxuICAgICAgICAgICAgdHlwZTogXCJib29sZWFuXCIsXG4gICAgICAgICAgICBncm91cDogXCJTdGF0dXNcIixcbiAgICAgICAgICAgIGdldHRlcjogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLl9pbnRlcm5hbC53b3JraW5nO1xuICAgICAgICAgICAgfVxuICAgICAgICB9ICAgICAgICAgIFxuICAgIH0sXG4gICAgcHJvdG90eXBlRXh0ZW5zaW9uczoge1xuICAgIH1cbn0pO1xuXG4vKiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIFxuICAgVGhpbmcgU3RhdGVcbiAgIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gKi9cbnZhciBtb2RlbFBvcnRzSGFzaCA9IHt9O1xuXG52YXIgVGhpbmdTdGF0ZURlZmluaXRpb24gPSB7XG4gICAgbmFtZTogXCJUaGluZyBTdGF0ZVwiLFxuICAgIGNhdGVnb3J5OiBcIkFXUyBJb1RcIixcbiAgICBjb2xvcjogXCJkYXRhXCIsICAgICAgICAgICBcbiAgICBpbml0aWFsaXplOiBmdW5jdGlvbigpIHtcbiAgICAgIHZhciBpbnRlcm5hbCA9IHRoaXMuX2ludGVybmFsO1xuICAgICAgaW50ZXJuYWwuaW5wdXRWYWx1ZXMgPSB7fTtcbiAgICAgIGludGVybmFsLnN0YXRlVmFsdWVzID0ge307XG4gICAgfSxcbiAgICBvdXRwdXRzOnsgICBcbiAgICAgIHN0b3JlZDp7XG4gICAgICAgIHR5cGU6J3NpZ25hbCcsXG4gICAgICAgIGRpc3BsYXlOYW1lOidTdG9yZWQnLFxuICAgICAgICBncm91cDonRXZlbnRzJyxcbiAgICAgIH0gICAgICAgXG4gICAgfSxcbiAgICBpbnB1dHM6eyBcbiAgICAgIGlkOntcbiAgICAgICAgdHlwZTonc3RyaW5nJyxcbiAgICAgICAgZGlzcGxheU5hbWU6J0lkJyxcbiAgICAgICAgZ3JvdXA6J0dlbmVyYWwnLFxuICAgICAgICBzZXQ6ZnVuY3Rpb24odmFsdWUpIHtcbiAgICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuXG4gICAgICAgICAgaWYodmFsdWUgPT0gdW5kZWZpbmVkIHx8IHZhbHVlID09PSBcIlwiKSByZXR1cm47XG4gICAgICAgICAgaWYodGhpcy5faW50ZXJuYWwudGhpbmdJZCA9PT0gdmFsdWUpIHJldHVybjtcbiAgICAgICAgICBpZih0aGlzLl9pbnRlcm5hbC50aGluZ0lkKVxuICAgICAgICAgICAgVGhpbmdTdGF0ZS5pbnN0YW5jZS51bnJlZ2lzdGVyKHRoaXMuX2ludGVybmFsLnRoaW5nSWQsdGhpcy5faW50ZXJuYWwudGhpbmdIYW5kbGVycyk7XG5cbiAgICAgICAgICB0aGlzLl9pbnRlcm5hbC50aGluZ0lkID0gdmFsdWU7XG4gICAgICAgICAgdGhpcy5faW50ZXJuYWwudGhpbmdIYW5kbGVycyA9IHtcbiAgICAgICAgICAgIG9uUmVnaXN0ZXJlZDpmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgVGhpbmdTdGF0ZS5pbnN0YW5jZS5nZXQoX3RoaXMuX2ludGVybmFsLnRoaW5nSWQsZnVuY3Rpb24oc3RhdGUpIHtcbiAgICAgICAgICAgICAgICBfdGhpcy5faW50ZXJuYWwuc3RhdGVWYWx1ZXMgPSBzdGF0ZTtcbiAgICAgICAgICAgICAgICBmb3IodmFyIGkgaW4gc3RhdGUpIHtcbiAgICAgICAgICAgICAgICAgIGlmKF90aGlzLmhhc091dHB1dChpKSlcbiAgICAgICAgICAgICAgICAgICAgX3RoaXMuZmxhZ091dHB1dERpcnR5KGkpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgb25EZWx0YTpmdW5jdGlvbihzdGF0ZSkge1xuICAgICAgICAgICAgICBmb3IodmFyIGkgaW4gc3RhdGUpIHtcbiAgICAgICAgICAgICAgICBfdGhpcy5faW50ZXJuYWwuc3RhdGVWYWx1ZXNbaV0gPSBzdGF0ZVtpXTtcbiAgICAgICAgICAgICAgICBpZihfdGhpcy5oYXNPdXRwdXQoaSkpXG4gICAgICAgICAgICAgICAgICAgIF90aGlzLmZsYWdPdXRwdXREaXJ0eShpKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgICBUaGluZ1N0YXRlLmluc3RhbmNlLnJlZ2lzdGVyKHRoaXMuX2ludGVybmFsLnRoaW5nSWQsdGhpcy5faW50ZXJuYWwudGhpbmdIYW5kbGVycyk7XG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBwcm9wZXJ0aWVzOntcbiAgICAgICAgdHlwZTp7bmFtZTonc3RyaW5nbGlzdCcsIGFsbG93RWRpdE9ubHk6dHJ1ZX0sXG4gICAgICAgIGRpc3BsYXlOYW1lOidQcm9wZXJ0aWVzJyxcbiAgICAgICAgZ3JvdXA6J1Byb3BlcnRpZXMnLFxuICAgICAgICBzZXQ6ZnVuY3Rpb24odmFsdWUpIHtcbiAgICAgICAgfVxuICAgICAgfSwgICAgIFxuICAgICAgc3RvcmU6e1xuICAgICAgICBkaXNwbGF5TmFtZTonU3RvcmUnLCAgICBcbiAgICAgICAgZ3JvdXA6J0FjdGlvbnMnLCAgXG4gICAgICAgIHZhbHVlQ2hhbmdlZFRvVHJ1ZTpmdW5jdGlvbigpIHtcbiAgICAgICAgICB0aGlzLnNjaGVkdWxlU3RvcmUoKTtcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIGNsZWFyOntcbiAgICAgICAgZGlzcGxheU5hbWU6J0NsZWFyJywgIFxuICAgICAgICBncm91cDonQWN0aW9ucycsICAgICAgICAgICAgICBcbiAgICAgICAgdmFsdWVDaGFuZ2VkVG9UcnVlOmZ1bmN0aW9uKCkge1xuICAgICAgICAvKiAgdmFyIGludGVybmFsID0gdGhpcy5faW50ZXJuYWw7XG4gICAgICAgICAgaWYoIWludGVybmFsLm1vZGVsKSByZXR1cm47XG4gICAgICAgICAgZm9yKHZhciBpIGluIGludGVybmFsLmlucHV0VmFsdWVzKSB7XG4gICAgICAgICAgICBpbnRlcm5hbC5tb2RlbC5zZXQoaSx1bmRlZmluZWQse3Jlc29sdmU6dHJ1ZX0pO1xuICAgICAgICAgIH0qL1xuICAgICAgICB9ICBcbiAgICAgIH0gICAgICAgICAgXG4gICAgfSxcbiAgICBwcm90b3R5cGVFeHRlbnNpb25zOntcbiAgICAgIHNjaGVkdWxlU3RvcmU6ZnVuY3Rpb24oKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG5cbiAgICAgICAgaWYodGhpcy5oYXNTY2hlZHVsZWRTdG9yZSkgcmV0dXJuO1xuICAgICAgICB0aGlzLmhhc1NjaGVkdWxlZFN0b3JlID0gdHJ1ZTtcblxuICAgICAgICB2YXIgaW50ZXJuYWwgPSB0aGlzLl9pbnRlcm5hbDtcbiAgICAgICAgdGhpcy5zY2hlZHVsZUFmdGVySW5wdXRzSGF2ZVVwZGF0ZWQoZnVuY3Rpb24oKXtcbiAgICAgICAgICBfdGhpcy5zZW5kU2lnbmFsT25PdXRwdXQoJ3N0b3JlZCcpO1xuICAgICAgICAgIF90aGlzLmhhc1NjaGVkdWxlZFN0b3JlID0gZmFsc2U7IFxuXG4gICAgICAgICAgVGhpbmdTdGF0ZS5pbnN0YW5jZS51cGRhdGUoaW50ZXJuYWwudGhpbmdJZCxpbnRlcm5hbC5pbnB1dFZhbHVlcyxmdW5jdGlvbigpIHtcbiAgICAgICAgICAgXG4gICAgICAgICAgfSk7XG5cbiAgICAgICAgfSk7XG4gICAgICB9LFxuICAgICAgX29uTm9kZURlbGV0ZWQ6IGZ1bmN0aW9uKCkge1xuICAgICAgICBpZih0aGlzLl9pbnRlcm5hbC50aGluZ0lkICE9PSB1bmRlZmluZWQgJiYgdGhpcy5faW50ZXJuYWwudGhpbmdJZCAhPT0gXCJcIilcbiAgICAgICAgICBUaGluZ1N0YXRlLmluc3RhbmNlLnVucmVnaXN0ZXIodGhpcy5faW50ZXJuYWwudGhpbmdJZCx0aGlzLl9pbnRlcm5hbC50aGluZ0hhbmRsZXJzKTtcbiAgICAgIH0sXG4gICAgICByZWdpc3Rlck91dHB1dElmTmVlZGVkOiBmdW5jdGlvbihuYW1lKSB7XG4gICAgICAgIGlmKHRoaXMuaGFzT3V0cHV0KG5hbWUpKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLnJlZ2lzdGVyT3V0cHV0KG5hbWUsIHtcbiAgICAgICAgICAgIGdldHRlcjogdXNlck91dHB1dEdldHRlci5iaW5kKHRoaXMsIG5hbWUpXG4gICAgICAgIH0pO1xuICAgICAgfSxcbiAgICAgIHJlZ2lzdGVySW5wdXRJZk5lZWRlZDogZnVuY3Rpb24obmFtZSkge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICBcbiAgICAgICAgaWYodGhpcy5oYXNJbnB1dChuYW1lKSkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIFxuICAgICAgICB0aGlzLnJlZ2lzdGVySW5wdXQobmFtZSwge1xuICAgICAgICAgICAgc2V0OiB1c2VySW5wdXRTZXR0ZXIuYmluZCh0aGlzLCBuYW1lKVxuICAgICAgICB9KTtcbiAgICAgIH0sICAgICAgICAgICAgICAgXG4gICAgfVxufTtcblxuZnVuY3Rpb24gdXNlck91dHB1dEdldHRlcihuYW1lKSB7XG4gICAgLyoganNoaW50IHZhbGlkdGhpczp0cnVlICovXG4gICAgcmV0dXJuIHRoaXMuX2ludGVybmFsLnN0YXRlVmFsdWVzW25hbWVdO1xuICAgIC8vcmV0dXJuIHRoaXMuX2ludGVybmFsLm1vZGVsP3RoaXMuX2ludGVybmFsLm1vZGVsLmdldChuYW1lLHtyZXNvbHZlOnRydWV9KTp1bmRlZmluZWQ7XG59XG5cbmZ1bmN0aW9uIHVzZXJJbnB1dFNldHRlcihuYW1lLHZhbHVlKSB7XG4gIC8qIGpzaGludCB2YWxpZHRoaXM6dHJ1ZSAqL1xuICB0aGlzLl9pbnRlcm5hbC5pbnB1dFZhbHVlc1tuYW1lXSA9IHZhbHVlO1xuICAvL3RoaXMuc2NoZWR1bGVTdG9yZSgpO1xufVxuXG5mdW5jdGlvbiB1cGRhdGVQb3J0cyhub2RlSWQsIHByb3BlcnRpZXMsIGVkaXRvckNvbm5lY3Rpb24pIHtcbiAgICB2YXIgcG9ydHMgPSBbXTtcblxuICAgIC8vIEFkZCB2YWx1ZSBvdXRwdXRzXG4gICAgcHJvcGVydGllcyA9IHByb3BlcnRpZXMgPyBwcm9wZXJ0aWVzLnNwbGl0KCcsJykgOiB1bmRlZmluZWQ7XG4gICAgZm9yKHZhciBpIGluIHByb3BlcnRpZXMpIHtcbiAgICAgICAgdmFyIHAgPSBwcm9wZXJ0aWVzW2ldO1xuICAgICAgICBcbiAgICAgICAgcG9ydHMucHVzaCh7XG4gICAgICAgICAgdHlwZTp7bmFtZTonKicsXG4gICAgICAgICAgICAgICAgYWxsb3dDb25uZWN0aW9uc09ubHk6dHJ1ZX0sXG4gICAgICAgICAgcGx1ZzonaW5wdXQvb3V0cHV0JyxcbiAgICAgICAgICBncm91cDonUHJvcGVydGllcycsXG4gICAgICAgICAgbmFtZTpwLFxuICAgICAgICB9KTtcblxuICAgIH1cblxuICAgIHZhciBoYXNoID0gSlNPTi5zdHJpbmdpZnkocG9ydHMpO1xuICAgIGlmKG1vZGVsUG9ydHNIYXNoW25vZGVJZF0gIT09IGhhc2gpIHsgLy8gTWFrZSBzdXJlIHdlIGRvbid0IHJlc2VuZCB0aGUgc2FtZSBwb3J0IGRhdGFcbiAgICAgICAgbW9kZWxQb3J0c0hhc2hbbm9kZUlkXSA9IGhhc2g7XG4gICAgICAgIGVkaXRvckNvbm5lY3Rpb24uc2VuZER5bmFtaWNQb3J0cyhub2RlSWQsIHBvcnRzKTtcbiAgICB9XG59XG5cbk5vb2RsLmRlZmluZU5vZGUoe1xuICAgIG5vZGU6IFRoaW5nU3RhdGVEZWZpbml0aW9uLFxuICAgIHNldHVwOiBmdW5jdGlvbihjb250ZXh0LCBncmFwaE1vZGVsKSB7XG5cbiAgICAgICAgaWYoIWNvbnRleHQuZWRpdG9yQ29ubmVjdGlvbiB8fCAhY29udGV4dC5lZGl0b3JDb25uZWN0aW9uLmlzUnVubmluZ0xvY2FsbHkoKSkge1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgZ3JhcGhNb2RlbC5vbihcIm5vZGVBZGRlZC5UaGluZyBTdGF0ZVwiLCBmdW5jdGlvbihub2RlKSB7XG4gICAgICAgICAgICBpZihub2RlLnBhcmFtZXRlcnMucHJvcGVydGllcykge1xuICAgICAgICAgICAgICAgIHVwZGF0ZVBvcnRzKG5vZGUuaWQsIG5vZGUucGFyYW1ldGVycy5wcm9wZXJ0aWVzLCBjb250ZXh0LmVkaXRvckNvbm5lY3Rpb24pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgbm9kZS5vbihcInBhcmFtZXRlclVwZGF0ZWRcIiwgZnVuY3Rpb24oZXZlbnQpIHtcbiAgICAgICAgICAgICAgICBpZihldmVudC5uYW1lID09PSBcInByb3BlcnRpZXNcIikge1xuICAgICAgICAgICAgICAgICAgICB1cGRhdGVQb3J0cyhub2RlLmlkLCAgbm9kZS5wYXJhbWV0ZXJzLnByb3BlcnRpZXMsIGNvbnRleHQuZWRpdG9yQ29ubmVjdGlvbik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgIH1cbn0pO1xuXG5Ob29kbC5wcm9qZWN0U2V0dGluZ3Moe1xuICAgIHBvcnRzOltcbiAgICAgICAge1xuICAgICAgICAgICAgZ3JvdXA6IFwiQVdTXCIsXG4gICAgICAgICAgICB0eXBlOiBcInN0cmluZ1wiLFxuICAgICAgICAgICAgbmFtZTogXCJhd3NJb1RSZWdpb25cIixcbiAgICAgICAgICAgIGRpc3BsYXlOYW1lOiBcIlJlZ2lvblwiLFxuICAgICAgICAgICAgZGVmYXVsdDogXCJ1cy1lYXN0LTFcIlxuICAgICAgICB9XG4gICAgXVxufSlcblxuTm9vZGwubW9kdWxlKGZ1bmN0aW9uKCkge1xuICBjb25zb2xlLmxvZygnU3RhcnRpbmcgQVdTLUlPVCBtb2R1bGUnKTtcblxuICAgIHNldFRpbWVvdXQoZnVuY3Rpb24oKSB7XG4gICAgICAgIFVzZXJNYW5hZ2VtZW50Lmluc3RhbmNlLmF0dGVtcHRDYWNoZWRTaWduSW4oKTsgIFxuICAgIH0sMSk7ICAgXG59KSIsIi8qXG4gKiBDb3B5cmlnaHQgMjAxMC0yMDE1IEFtYXpvbi5jb20sIEluYy4gb3IgaXRzIGFmZmlsaWF0ZXMuIEFsbCBSaWdodHMgUmVzZXJ2ZWQuXG4gKlxuICogTGljZW5zZWQgdW5kZXIgdGhlIEFwYWNoZSBMaWNlbnNlLCBWZXJzaW9uIDIuMCAodGhlIFwiTGljZW5zZVwiKS5cbiAqIFlvdSBtYXkgbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aCB0aGUgTGljZW5zZS5cbiAqIEEgY29weSBvZiB0aGUgTGljZW5zZSBpcyBsb2NhdGVkIGF0XG4gKlxuICogIGh0dHA6Ly9hd3MuYW1hem9uLmNvbS9hcGFjaGUyLjBcbiAqXG4gKiBvciBpbiB0aGUgXCJsaWNlbnNlXCIgZmlsZSBhY2NvbXBhbnlpbmcgdGhpcyBmaWxlLiBUaGlzIGZpbGUgaXMgZGlzdHJpYnV0ZWRcbiAqIG9uIGFuIFwiQVMgSVNcIiBCQVNJUywgV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlclxuICogZXhwcmVzcyBvciBpbXBsaWVkLiBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmdcbiAqIHBlcm1pc3Npb25zIGFuZCBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS5cbiAqL1xuXG4vL25vZGUuanMgZGVwc1xudmFyIGV2ZW50cyA9IHJlcXVpcmUoJ2V2ZW50cycpO1xudmFyIGluaGVyaXRzID0gcmVxdWlyZSgndXRpbCcpLmluaGVyaXRzO1xuXG4vL25wbSBkZXBzXG5cbi8vYXBwIGRlcHNcbnZhciBkZXZpY2VNb2R1bGUgPSB7fTtcblxudmFyIGlzVW5kZWZpbmVkID0gZnVuY3Rpb24odmFsdWUpIHtcbiAgIHJldHVybiB0eXBlb2YgdmFsdWUgPT09ICd1bmRlZmluZWQnIHx8IHR5cGVvZiB2YWx1ZSA9PT0gbnVsbDtcbn07XG5cbi8vXG4vLyBwcml2YXRlIGZ1bmN0aW9uc1xuLy9cbmZ1bmN0aW9uIGJ1aWxkVGhpbmdTaGFkb3dUb3BpYyh0aGluZ05hbWUsIG9wZXJhdGlvbiwgdHlwZSkge1xuICAgaWYgKCFpc1VuZGVmaW5lZCh0eXBlKSkge1xuICAgICAgcmV0dXJuICckYXdzL3RoaW5ncy8nICsgdGhpbmdOYW1lICsgJy9zaGFkb3cvJyArIG9wZXJhdGlvbiArICcvJyArIHR5cGU7XG4gICB9XG4gICByZXR1cm4gJyRhd3MvdGhpbmdzLycgKyB0aGluZ05hbWUgKyAnL3NoYWRvdy8nICsgb3BlcmF0aW9uO1xufVxuXG5mdW5jdGlvbiBpc1Jlc2VydmVkVG9waWModG9waWMpIHtcbiAgIGlmICh0b3BpYy5zdWJzdHJpbmcoMCwgMTIpID09PSAnJGF3cy90aGluZ3MvJykge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICB9XG4gICByZXR1cm4gZmFsc2U7XG59XG5cbmZ1bmN0aW9uIGlzVGhpbmdTaGFkb3dUb3BpYyh0b3BpY1Rva2VucywgZGlyZWN0aW9uKSB7XG4gICB2YXIgcmMgPSBmYWxzZTtcbiAgIGlmICh0b3BpY1Rva2Vuc1swXSA9PT0gJyRhd3MnKSB7XG4gICAgICAvL1xuICAgICAgLy8gVGhpbmcgc2hhZG93IHRvcGljcyBoYXZlIHRoZSBmb3JtOlxuICAgICAgLy9cbiAgICAgIC8vICAgICAgJGF3cy90aGluZ3Mve3RoaW5nTmFtZX0vc2hhZG93L3tPcGVyYXRpb259L3tTdGF0dXN9XG4gICAgICAvL1xuICAgICAgLy8gV2hlcmUge09wZXJhdGlvbn0gPT09IHVwZGF0ZXxnZXR8ZGVsZXRlXG4gICAgICAvLyAgIEFuZCAgICB7U3RhdHVzfSA9PT0gYWNjZXB0ZWR8cmVqZWN0ZWR8ZGVsdGFcbiAgICAgIC8vXG4gICAgICBpZiAoKHRvcGljVG9rZW5zWzFdID09PSAndGhpbmdzJykgJiZcbiAgICAgICAgICh0b3BpY1Rva2Vuc1szXSA9PT0gJ3NoYWRvdycpICYmXG4gICAgICAgICAoKHRvcGljVG9rZW5zWzRdID09PSAndXBkYXRlJykgfHxcbiAgICAgICAgICAgICh0b3BpY1Rva2Vuc1s0XSA9PT0gJ2dldCcpIHx8XG4gICAgICAgICAgICAodG9waWNUb2tlbnNbNF0gPT09ICdkZWxldGUnKSkpIHtcbiAgICAgICAgIC8vXG4gICAgICAgICAvLyBMb29rcyBnb29kIHNvIGZhcjsgbm93IGNoZWNrIHRoZSBkaXJlY3Rpb24gYW5kIHNlZSBpZlxuICAgICAgICAgLy8gc3RpbGwgbWFrZXMgc2Vuc2UuXG4gICAgICAgICAvL1xuICAgICAgICAgaWYgKGRpcmVjdGlvbiA9PT0gJ3N1YnNjcmliZScpIHtcbiAgICAgICAgICAgIGlmICgoKHRvcGljVG9rZW5zWzVdID09PSAnYWNjZXB0ZWQnKSB8fFxuICAgICAgICAgICAgICAgICAgKHRvcGljVG9rZW5zWzVdID09PSAncmVqZWN0ZWQnKSB8fFxuICAgICAgICAgICAgICAgICAgKHRvcGljVG9rZW5zWzVdID09PSAnZGVsdGEnKSkgJiZcbiAgICAgICAgICAgICAgICh0b3BpY1Rva2Vucy5sZW5ndGggPT09IDYpKSB7XG4gICAgICAgICAgICAgICByYyA9IHRydWU7XG4gICAgICAgICAgICB9XG4gICAgICAgICB9IGVsc2UgLy8gZGlyZWN0aW9uID09PSAncHVibGlzaCdcbiAgICAgICAgIHtcbiAgICAgICAgICAgIGlmICh0b3BpY1Rva2Vucy5sZW5ndGggPT09IDUpIHtcbiAgICAgICAgICAgICAgIHJjID0gdHJ1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgIH1cbiAgICAgIH1cbiAgIH1cbiAgIHJldHVybiByYztcbn1cblxuLy9iZWdpbiBtb2R1bGVcblxuZnVuY3Rpb24gVGhpbmdTaGFkb3dzQ2xpZW50KGRldmljZU9wdGlvbnMsIHRoaW5nU2hhZG93T3B0aW9ucykge1xuICAgLy9cbiAgIC8vIEZvcmNlIGluc3RhbnRpYXRpb24gdXNpbmcgdGhlICduZXcnIG9wZXJhdG9yOyB0aGlzIHdpbGwgY2F1c2UgaW5oZXJpdGVkXG4gICAvLyBjb25zdHJ1Y3RvcnMgKGUuZy4gdGhlICdldmVudHMnIGNsYXNzKSB0byBiZSBjYWxsZWQuXG4gICAvL1xuICAgaWYgKCEodGhpcyBpbnN0YW5jZW9mIFRoaW5nU2hhZG93c0NsaWVudCkpIHtcbiAgICAgIHJldHVybiBuZXcgVGhpbmdTaGFkb3dzQ2xpZW50KGRldmljZU9wdGlvbnMsIHRoaW5nU2hhZG93T3B0aW9ucyk7XG4gICB9XG5cbiAgIC8vXG4gICAvLyBBIGNvcHkgb2YgJ3RoaXMnIGZvciB1c2UgaW5zaWRlIG9mIGNsb3N1cmVzXG4gICAvL1xuICAgdmFyIHRoYXQgPSB0aGlzO1xuXG4gICAvL1xuICAgLy8gVHJhY2sgVGhpbmcgU2hhZG93IHJlZ2lzdHJhdGlvbnMgaW4gaGVyZS5cbiAgIC8vXG4gICB2YXIgdGhpbmdTaGFkb3dzID0gW3t9XTtcblxuICAgLy9cbiAgIC8vIEltcGxlbWVudHMgZm9yIGV2ZXJ5IG9wZXJhdGlvbiwgdXNlZCB0byBjb25zdHJ1Y3QgY2xpZW50VG9rZW4uXG4gICAvL1xuICAgdmFyIG9wZXJhdGlvbkNvdW50ID0gMDtcblxuICAgLy9cbiAgIC8vIE9wZXJhdGlvbiB0aW1lb3V0IChtaWxsaXNlY29uZHMpLiAgSWYgbm8gYWNjZXB0ZWQgb3IgcmVqZWN0ZWQgcmVzcG9uc2VcbiAgIC8vIHRvIGEgdGhpbmcgb3BlcmF0aW9uIGlzIHJlY2VpdmVkIHdpdGhpbiB0aGlzIHRpbWUsIHN1YnNjcmlwdGlvbnNcbiAgIC8vIHRvIHRoZSBhY2NlcHRlZCBhbmQgcmVqZWN0ZWQgc3ViLXRvcGljcyBmb3IgYSB0aGluZyBhcmUgY2FuY2VsbGVkLlxuICAgLy9cbiAgIHZhciBvcGVyYXRpb25UaW1lb3V0ID0gMTAwMDA7IC8qIG1pbGxpc2Vjb25kcyAqL1xuXG4gICAvL1xuICAgLy8gVmFyaWFibGUgdXNlZCBieSB0aGUgdGVzdGluZyBBUEkgc2V0Q29ubmVjdGlvblN0YXR1cygpIHRvIHNpbXVsYXRlXG4gICAvLyBuZXR3b3JrIGNvbm5lY3Rpdml0eSBmYWlsdXJlcy5cbiAgIC8vXG4gICB2YXIgY29ubmVjdGVkID0gdHJ1ZTtcblxuICAgLy9cbiAgIC8vIEluc3RhbnRpYXRlIHRoZSBkZXZpY2UuXG4gICAvL1xuICAgdmFyIGRldmljZSA9IGRldmljZU1vZHVsZS5EZXZpY2VDbGllbnQoZGV2aWNlT3B0aW9ucyk7XG5cbiAgIGlmICghaXNVbmRlZmluZWQodGhpbmdTaGFkb3dPcHRpb25zKSkge1xuICAgICAgaWYgKCFpc1VuZGVmaW5lZCh0aGluZ1NoYWRvd09wdGlvbnMub3BlcmF0aW9uVGltZW91dCkpIHtcbiAgICAgICAgIG9wZXJhdGlvblRpbWVvdXQgPSB0aGluZ1NoYWRvd09wdGlvbnMub3BlcmF0aW9uVGltZW91dDtcbiAgICAgIH1cbiAgIH1cblxuICAgLy9cbiAgIC8vIFByaXZhdGUgZnVuY3Rpb24gdG8gc3Vic2NyaWJlIGFuZCB1bnN1YnNjcmliZSBmcm9tIHRvcGljcy5cbiAgIC8vXG4gICB0aGlzLl9oYW5kbGVTdWJzY3JpcHRpb25zID0gZnVuY3Rpb24odGhpbmdOYW1lLCB0b3BpY1NwZWNzLCBkZXZGdW5jdGlvbiwgY2FsbGJhY2spIHtcbiAgICAgIHZhciB0b3BpY3MgPSBbXTtcblxuICAgICAgLy9cbiAgICAgIC8vIEJ1aWxkIGFuIGFycmF5IG9mIHRvcGljIG5hbWVzLlxuICAgICAgLy9cbiAgICAgIGZvciAodmFyIGkgPSAwLCB0b3BpY3NMZW4gPSB0b3BpY1NwZWNzLmxlbmd0aDsgaSA8IHRvcGljc0xlbjsgaSsrKSB7XG4gICAgICAgICBmb3IgKHZhciBqID0gMCwgb3BzTGVuID0gdG9waWNTcGVjc1tpXS5vcGVyYXRpb25zLmxlbmd0aDsgaiA8IG9wc0xlbjsgaisrKSB7XG4gICAgICAgICAgICBmb3IgKHZhciBrID0gMCwgc3RhdExlbiA9IHRvcGljU3BlY3NbaV0uc3RhdGlpLmxlbmd0aDsgayA8IHN0YXRMZW47IGsrKykge1xuICAgICAgICAgICAgICAgdG9waWNzLnB1c2goYnVpbGRUaGluZ1NoYWRvd1RvcGljKHRoaW5nTmFtZSxcbiAgICAgICAgICAgICAgICAgIHRvcGljU3BlY3NbaV0ub3BlcmF0aW9uc1tqXSxcbiAgICAgICAgICAgICAgICAgIHRvcGljU3BlY3NbaV0uc3RhdGlpW2tdKSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmICh0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS5kZWJ1ZyA9PT0gdHJ1ZSkge1xuICAgICAgICAgY29uc29sZS5sb2coZGV2RnVuY3Rpb24gKyAnIG9uICcgKyB0b3BpY3MpO1xuICAgICAgfVxuICAgICAgLy9cbiAgICAgIC8vIFN1YnNjcmliZS91bnN1YnNjcmliZSBmcm9tIHRoZSB0b3BpY3MgYW5kIHBlcmZvcm0gY2FsbGJhY2sgd2hlbiBjb21wbGV0ZS5cbiAgICAgIC8vXG4gICAgICB2YXIgYXJncyA9IFtdO1xuICAgICAgYXJncy5wdXNoKHRvcGljcyk7XG4gICAgICBpZiAoZGV2RnVuY3Rpb24gPT09ICdzdWJzY3JpYmUnKSB7XG4gICAgICAgICAvLyBRb1Mgb25seSBhcHBsaWNhYmxlIGZvciBzdWJzY3JpYmVcbiAgICAgICAgIGFyZ3MucHVzaCh7XG4gICAgICAgICAgICBxb3M6IHRoaW5nU2hhZG93c1t0aGluZ05hbWVdLnFvc1xuICAgICAgICAgfSk7XG4gICAgICAgICAvLyBhZGQgb3VyIGNhbGxiYWNrIHRvIGNoZWNrIHRoZSBTVUJBQ0sgcmVzcG9uc2UgZm9yIGdyYW50ZWQgc3Vic2NyaXB0aW9uc1xuICAgICAgICAgYXJncy5wdXNoKGZ1bmN0aW9uKGVyciwgZ3JhbnRlZCkge1xuICAgICAgICAgICAgaWYgKCFpc1VuZGVmaW5lZChjYWxsYmFjaykpIHtcbiAgICAgICAgICAgICAgIGlmIChlcnIpIHtcbiAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKGVycik7XG4gICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAvL1xuICAgICAgICAgICAgICAgLy8gQ2hlY2sgdG8gc2VlIGlmIHdlIGdvdCBhbGwgdG9waWMgc3Vic2NyaXB0aW9ucyBncmFudGVkLlxuICAgICAgICAgICAgICAgLy9cbiAgICAgICAgICAgICAgIHZhciBmYWlsZWRUb3BpY3MgPSBbXTtcbiAgICAgICAgICAgICAgIGZvciAodmFyIGsgPSAwLCBncmFudGVkTGVuID0gZ3JhbnRlZC5sZW5ndGg7IGsgPCBncmFudGVkTGVuOyBrKyspIHtcbiAgICAgICAgICAgICAgICAgIC8vXG4gICAgICAgICAgICAgICAgICAvLyAxMjggaXMgMHg4MCAtIEZhaWx1cmUgZnJvbSB0aGUgTVFUVCBsaWIuXG4gICAgICAgICAgICAgICAgICAvL1xuICAgICAgICAgICAgICAgICAgaWYgKGdyYW50ZWRba10ucW9zID09PSAxMjgpIHtcbiAgICAgICAgICAgICAgICAgICAgIGZhaWxlZFRvcGljcy5wdXNoKGdyYW50ZWRba10pO1xuICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICBpZiAoZmFpbGVkVG9waWNzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgICAgICAgIGNhbGxiYWNrKCdOb3QgYWxsIHN1YnNjcmlwdGlvbnMgd2VyZSBncmFudGVkJywgZmFpbGVkVG9waWNzKTtcbiAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgLy8gYWxsIHN1YnNjcmlwdGlvbnMgd2VyZSBncmFudGVkXG4gICAgICAgICAgICAgICBjYWxsYmFjaygpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAgaWYgKCFpc1VuZGVmaW5lZChjYWxsYmFjaykpIHtcbiAgICAgICAgICAgIGFyZ3MucHVzaChjYWxsYmFjayk7XG4gICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGRldmljZVtkZXZGdW5jdGlvbl0uYXBwbHkoZGV2aWNlLCBhcmdzKTtcbiAgIH07XG5cbiAgIC8vXG4gICAvLyBQcml2YXRlIGZ1bmN0aW9uIHRvIGhhbmRsZSBtZXNzYWdlcyBhbmQgZGlzcGF0Y2ggdGhlbSBhY2NvcmRpbmdseS5cbiAgIC8vXG4gICB0aGlzLl9oYW5kbGVNZXNzYWdlcyA9IGZ1bmN0aW9uKHRoaW5nTmFtZSwgb3BlcmF0aW9uLCBvcGVyYXRpb25TdGF0dXMsIHBheWxvYWQpIHtcbiAgICAgIHZhciBzdGF0ZU9iamVjdCA9IHt9O1xuICAgICAgdHJ5IHtcbiAgICAgICAgIHN0YXRlT2JqZWN0ID0gSlNPTi5wYXJzZShwYXlsb2FkLnRvU3RyaW5nKCkpO1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgICBpZiAoZGV2aWNlT3B0aW9ucy5kZWJ1ZyA9PT0gdHJ1ZSkge1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcignZmFpbGVkIHBhcnNpbmcgSlNPTiBcXCcnICsgcGF5bG9hZC50b1N0cmluZygpICsgJ1xcJywgJyArIGVycik7XG4gICAgICAgICB9XG4gICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICB2YXIgY2xpZW50VG9rZW4gPSBzdGF0ZU9iamVjdC5jbGllbnRUb2tlbjtcbiAgICAgIHZhciB2ZXJzaW9uID0gc3RhdGVPYmplY3QudmVyc2lvbjtcbiAgICAgIC8vXG4gICAgICAvLyBSZW1vdmUgdGhlIHByb3BlcnRpZXMgJ2NsaWVudFRva2VuJyBhbmQgJ3ZlcnNpb24nIGZyb20gdGhlIHN0YXRlT2JqZWN0O1xuICAgICAgLy8gdGhlc2UgcHJvcGVydGllcyBhcmUgaW50ZXJuYWwgdG8gdGhpcyBjbGFzcy5cbiAgICAgIC8vXG4gICAgICBkZWxldGUgc3RhdGVPYmplY3QuY2xpZW50VG9rZW47XG4gICAgICBkZWxldGUgc3RhdGVPYmplY3QudmVyc2lvbjtcbiAgICAgIC8vXG4gICAgICAvLyBVcGRhdGUgdGhlIHRoaW5nIHZlcnNpb24gb24gZXZlcnkgYWNjZXB0ZWQgb3IgZGVsdGEgbWVzc2FnZSB3aGljaCBcbiAgICAgIC8vIGNvbnRhaW5zIGl0LlxuICAgICAgLy9cbiAgICAgIGlmICgoIWlzVW5kZWZpbmVkKHZlcnNpb24pKSAmJiAob3BlcmF0aW9uU3RhdHVzICE9PSAncmVqZWN0ZWQnKSkge1xuICAgICAgICAgLy9cbiAgICAgICAgIC8vIFRoZSB0aGluZyBzaGFkb3cgdmVyc2lvbiBpcyBpbmNyZW1lbnRlZCBieSBBV1MgSW9UIGFuZCBzaG91bGQgYWx3YXlzXG4gICAgICAgICAvLyBpbmNyZWFzZS4gIERvIG5vdCB1cGRhdGUgb3VyIGxvY2FsIHZlcnNpb24gaWYgdGhlIHJlY2VpdmVkIHZlcnNpb24gaXNcbiAgICAgICAgIC8vIGxlc3MgdGhhbiBvdXIgdmVyc2lvbi4gIFxuICAgICAgICAgLy9cbiAgICAgICAgIGlmICgoaXNVbmRlZmluZWQodGhpbmdTaGFkb3dzW3RoaW5nTmFtZV0udmVyc2lvbikpIHx8XG4gICAgICAgICAgICAodmVyc2lvbiA+PSB0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS52ZXJzaW9uKSkge1xuICAgICAgICAgICAgdGhpbmdTaGFkb3dzW3RoaW5nTmFtZV0udmVyc2lvbiA9IHZlcnNpb247XG4gICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgLy9cbiAgICAgICAgICAgIC8vIFdlJ3ZlIHJlY2VpdmVkIGEgbWVzc2FnZSBmcm9tIEFXUyBJb1Qgd2l0aCBhIHZlcnNpb24gbnVtYmVyIGxvd2VyIHRoYW5cbiAgICAgICAgICAgIC8vIHdlIHdvdWxkIGV4cGVjdC4gIFRoZXJlIGFyZSB0d28gdGhpbmdzIHRoYXQgY2FuIGNhdXNlIHRoaXM6XG4gICAgICAgICAgICAvL1xuICAgICAgICAgICAgLy8gIDEpIFRoZSBzaGFkb3cgaGFzIGJlZW4gZGVsZXRlZCAodmVyc2lvbiAjIHJldmVydHMgdG8gMSBpbiB0aGlzIGNhc2UuKVxuICAgICAgICAgICAgLy8gIDIpIFRoZSBtZXNzYWdlIGhhcyBhcnJpdmVkIG91dC1vZi1vcmRlci5cbiAgICAgICAgICAgIC8vXG4gICAgICAgICAgICAvLyBGb3IgY2FzZSAxKSB3ZSBjYW4gbG9vayBhdCB0aGUgb3BlcmF0aW9uIHRvIGRldGVybWluZSB0aGF0IHRoaXNcbiAgICAgICAgICAgIC8vIGlzIHRoZSBjYXNlIGFuZCBub3RpZnkgdGhlIGNsaWVudCBpZiBhcHByb3ByaWF0ZS4gIEZvciBjYXNlIDIsIFxuICAgICAgICAgICAgLy8gd2Ugd2lsbCBub3QgcHJvY2VzcyBpdCB1bmxlc3MgdGhlIGNsaWVudCBoYXMgc3BlY2lmaWNhbGx5IGV4cHJlc3NlZFxuICAgICAgICAgICAgLy8gYW4gaW50ZXJlc3RlZCBpbiB0aGVzZSBtZXNzYWdlcyBieSBzZXR0aW5nICdkaXNjYXJkU3RhbGUnIHRvIGZhbHNlLlxuICAgICAgICAgICAgLy9cbiAgICAgICAgICAgIGlmIChvcGVyYXRpb24gIT09ICdkZWxldGUnICYmIHRoaW5nU2hhZG93c1t0aGluZ05hbWVdLmRpc2NhcmRTdGFsZSA9PT0gdHJ1ZSkge1xuICAgICAgICAgICAgICAgaWYgKGRldmljZU9wdGlvbnMuZGVidWcgPT09IHRydWUpIHtcbiAgICAgICAgICAgICAgICAgIGNvbnNvbGUud2Fybignb3V0LW9mLWRhdGUgdmVyc2lvbiBcXCcnICsgdmVyc2lvbiArICdcXCcgb24gXFwnJyArXG4gICAgICAgICAgICAgICAgICAgICB0aGluZ05hbWUgKyAnXFwnIChsb2NhbCB2ZXJzaW9uIFxcJycgK1xuICAgICAgICAgICAgICAgICAgICAgdGhpbmdTaGFkb3dzW3RoaW5nTmFtZV0udmVyc2lvbiArICdcXCcpJyk7XG4gICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICB9XG4gICAgICB9XG4gICAgICAvL1xuICAgICAgLy8gSWYgdGhpcyBpcyBhICdkZWx0YScgbWVzc2FnZSwgZW1pdCBhbiBldmVudCBmb3IgaXQgYW5kIHJldHVybi5cbiAgICAgIC8vXG4gICAgICBpZiAob3BlcmF0aW9uU3RhdHVzID09PSAnZGVsdGEnKSB7XG4gICAgICAgICB0aGlzLmVtaXQoJ2RlbHRhJywgdGhpbmdOYW1lLCBzdGF0ZU9iamVjdCk7XG4gICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICAvL1xuICAgICAgLy8gb25seSBhY2NlcHRlZC9yZWplY3RlZCBtZXNzYWdlcyBwYXN0IHRoaXMgcG9pbnRcbiAgICAgIC8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4gICAgICAvLyBJZiB0aGlzIGlzIGFuIHVua293biBjbGllbnRUb2tlbiAoZS5nLiwgaXQgZG9lc24ndCBoYXZlIGEgY29ycmVzcG9uZGluZ1xuICAgICAgLy8gY2xpZW50IHRva2VuIHByb3BlcnR5LCB0aGUgc2hhZG93IGhhcyBiZWVuIG1vZGlmaWVkIGJ5IGFub3RoZXIgY2xpZW50LlxuICAgICAgLy8gSWYgaXQncyBhbiB1cGRhdGUvYWNjZXB0ZWQgb3IgZGVsZXRlL2FjY2VwdGVkLCB1cGRhdGUgdGhlIHNoYWRvdyBhbmRcbiAgICAgIC8vIG5vdGlmeSB0aGUgY2xpZW50LlxuICAgICAgLy9cbiAgICAgIGlmIChpc1VuZGVmaW5lZCh0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS5jbGllbnRUb2tlbikgfHxcbiAgICAgICAgIHRoaW5nU2hhZG93c1t0aGluZ05hbWVdLmNsaWVudFRva2VuICE9PSBjbGllbnRUb2tlbikge1xuICAgICAgICAgaWYgKChvcGVyYXRpb25TdGF0dXMgPT09ICdhY2NlcHRlZCcpICYmIChvcGVyYXRpb24gIT09ICdnZXQnKSkge1xuICAgICAgICAgICAgLy9cbiAgICAgICAgICAgIC8vIFRoaXMgaXMgYSBmb3JlaWduIHVwZGF0ZSBvciBkZWxldGUgYWNjZXB0ZWQsIHVwZGF0ZSBvdXJcbiAgICAgICAgICAgIC8vIHNoYWRvdyB3aXRoIHRoZSBsYXRlc3Qgc3RhdGUgYW5kIHNlbmQgYSBub3RpZmljYXRpb24uXG4gICAgICAgICAgICAvL1xuICAgICAgICAgICAgdGhpcy5lbWl0KCdmb3JlaWduU3RhdGVDaGFuZ2UnLCB0aGluZ05hbWUsIG9wZXJhdGlvbiwgc3RhdGVPYmplY3QpO1xuICAgICAgICAgfVxuICAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgLy9cbiAgICAgIC8vIEEgcmVzcG9uc2UgaGFzIGJlZW4gcmVjZWl2ZWQsIHNvIGNhbmNlbCBhbnkgb3V0c3RhbmRpbmcgdGltZW91dCBvbiB0aGlzXG4gICAgICAvLyB0aGluZ05hbWUvY2xpZW50VG9rZW4sIGRlbGV0ZSB0aGUgdGltZW91dCBoYW5kbGUsIGFuZCB1bnN1YnNjcmliZSBmcm9tXG4gICAgICAvLyBhbGwgc3ViLXRvcGljcy5cbiAgICAgIC8vXG4gICAgICBjbGVhclRpbWVvdXQoXG4gICAgICAgICB0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS50aW1lb3V0KTtcblxuICAgICAgZGVsZXRlIHRoaW5nU2hhZG93c1t0aGluZ05hbWVdLnRpbWVvdXQ7XG4gICAgICAvL1xuICAgICAgLy8gRGVsZXRlIHRoZSBvcGVyYXRpb24ncyBjbGllbnQgdG9rZW4uXG4gICAgICAvL1xuICAgICAgZGVsZXRlIHRoaW5nU2hhZG93c1t0aGluZ05hbWVdLmNsaWVudFRva2VuO1xuICAgICAgLy9cbiAgICAgIC8vIE1hcmsgdGhpcyBvcGVyYXRpb24gYXMgY29tcGxldGUuXG4gICAgICAvL1xuICAgICAgdGhpbmdTaGFkb3dzW3RoaW5nTmFtZV0ucGVuZGluZyA9IGZhbHNlO1xuXG4gICAgICAvL1xuICAgICAgLy8gVW5zdWJzY3JpYmUgZnJvbSB0aGUgJ2FjY2VwdGVkJyBhbmQgJ3JlamVjdGVkJyBzdWItdG9waWNzIHVubGVzcyB3ZSBhcmVcbiAgICAgIC8vIHBlcnNpc3RlbnRseSBzdWJzY3JpYmVkIHRvIHRoaXMgdGhpbmcgc2hhZG93LlxuICAgICAgLy9cbiAgICAgIGlmICh0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS5wZXJzaXN0ZW50U3Vic2NyaWJlID09PSBmYWxzZSkge1xuICAgICAgICAgdGhpcy5faGFuZGxlU3Vic2NyaXB0aW9ucyh0aGluZ05hbWUsIFt7XG4gICAgICAgICAgICBvcGVyYXRpb25zOiBbb3BlcmF0aW9uXSxcbiAgICAgICAgICAgIHN0YXRpaTogWydhY2NlcHRlZCcsICdyZWplY3RlZCddXG4gICAgICAgICB9XSwgJ3Vuc3Vic2NyaWJlJyk7XG4gICAgICB9XG5cbiAgICAgIC8vXG4gICAgICAvLyBFbWl0IGFuIGV2ZW50IGRldGFpbGluZyB0aGUgb3BlcmF0aW9uIHN0YXR1czsgdGhlIGNsaWVudFRva2VuIGlzIGluY2x1ZGVkXG4gICAgICAvLyBhcyBhbiBhcmd1bWVudCBzbyB0aGF0IHRoZSBhcHBsaWNhdGlvbiBjYW4gY29ycmVsYXRlIHN0YXR1cyBldmVudHMgdG9cbiAgICAgIC8vIHRoZSBvcGVyYXRpb25zIHRoZXkgYXJlIGFzc29jaWF0ZWQgd2l0aC5cbiAgICAgIC8vXG4gICAgICB0aGlzLmVtaXQoJ3N0YXR1cycsIHRoaW5nTmFtZSwgb3BlcmF0aW9uU3RhdHVzLCBjbGllbnRUb2tlbiwgc3RhdGVPYmplY3QpO1xuICAgfTtcblxuICAgZGV2aWNlLm9uKCdjb25uZWN0JywgZnVuY3Rpb24oKSB7XG4gICAgICB0aGF0LmVtaXQoJ2Nvbm5lY3QnKTtcbiAgIH0pO1xuICAgZGV2aWNlLm9uKCdjbG9zZScsIGZ1bmN0aW9uKCkge1xuICAgICAgdGhhdC5lbWl0KCdjbG9zZScpO1xuICAgfSk7XG4gICBkZXZpY2Uub24oJ3JlY29ubmVjdCcsIGZ1bmN0aW9uKCkge1xuICAgICAgdGhhdC5lbWl0KCdyZWNvbm5lY3QnKTtcbiAgIH0pO1xuICAgZGV2aWNlLm9uKCdvZmZsaW5lJywgZnVuY3Rpb24oKSB7XG4gICAgICB0aGF0LmVtaXQoJ29mZmxpbmUnKTtcbiAgIH0pO1xuICAgZGV2aWNlLm9uKCdlcnJvcicsIGZ1bmN0aW9uKGVycm9yKSB7XG4gICAgICB0aGF0LmVtaXQoJ2Vycm9yJywgZXJyb3IpO1xuICAgfSk7XG4gICBkZXZpY2Uub24oJ21lc3NhZ2UnLCBmdW5jdGlvbih0b3BpYywgcGF5bG9hZCkge1xuXG4gICAgICBpZiAoY29ubmVjdGVkID09PSB0cnVlKSB7XG4gICAgICAgICAvL1xuICAgICAgICAgLy8gUGFyc2UgdGhlIHRvcGljIHRvIGRldGVybWluZSB3aGF0IHRvIGRvIHdpdGggaXQuXG4gICAgICAgICAvL1xuICAgICAgICAgdmFyIHRvcGljVG9rZW5zID0gdG9waWMuc3BsaXQoJy8nKTtcbiAgICAgICAgIC8vXG4gICAgICAgICAvLyBGaXJzdCwgZG8gYSByb3VnaCBjaGVjayB0byBzZWUgaWYgd2Ugc2hvdWxkIGNvbnRpbnVlIG9yIG5vdC5cbiAgICAgICAgIC8vXG4gICAgICAgICBpZiAoaXNUaGluZ1NoYWRvd1RvcGljKHRvcGljVG9rZW5zLCAnc3Vic2NyaWJlJykpIHtcbiAgICAgICAgICAgIC8vXG4gICAgICAgICAgICAvLyBUaGlzIGxvb2tzIGxpa2UgYSB2YWxpZCBUaGluZyB0b3BpYywgc28gc2VlIGlmIHRoZSBUaGluZyBpcyBpbiB0aGVcbiAgICAgICAgICAgIC8vIHJlZ2lzdGVyZWQgVGhpbmcgdGFibGUuXG4gICAgICAgICAgICAvL1xuICAgICAgICAgICAgaWYgKHRoaW5nU2hhZG93cy5oYXNPd25Qcm9wZXJ0eSh0b3BpY1Rva2Vuc1syXSkpIHtcbiAgICAgICAgICAgICAgIC8vXG4gICAgICAgICAgICAgICAvLyBUaGlzIGlzIGEgcmVnaXN0ZXJlZCBUaGluZywgc28gcGVyZm9ybSBtZXNzYWdlIGhhbmRsaW5nIG9uIGl0LlxuICAgICAgICAgICAgICAgLy9cbiAgICAgICAgICAgICAgIHRoYXQuX2hhbmRsZU1lc3NhZ2VzKHRvcGljVG9rZW5zWzJdLCAvLyB0aGluZ05hbWVcbiAgICAgICAgICAgICAgICAgIHRvcGljVG9rZW5zWzRdLCAvLyBvcGVyYXRpb25cbiAgICAgICAgICAgICAgICAgIHRvcGljVG9rZW5zWzVdLCAvLyBzdGF0dXNcbiAgICAgICAgICAgICAgICAgIHBheWxvYWQpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgLy9cbiAgICAgICAgICAgIC8vIEFueSBtZXNzYWdlcyByZWNlaXZlZCBmb3IgdW5yZWdpc3RlcmVkIFRoaW5ncyBmYWxsIGhlcmUgYW5kIGFyZSBpZ25vcmVkLlxuICAgICAgICAgICAgLy9cbiAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAvL1xuICAgICAgICAgICAgLy8gVGhpcyBpc24ndCBhIFRoaW5nIHRvcGljLCBzbyBwYXNzIGl0IGFsb25nIHRvIHRoZSBpbnN0YW5jZSBpZiB0aGV5IGhhdmVcbiAgICAgICAgICAgIC8vIGluZGljYXRlZCB0aGV5IHdhbnQgdG8gaGFuZGxlIGl0LlxuICAgICAgICAgICAgLy9cbiAgICAgICAgICAgIHRoYXQuZW1pdCgnbWVzc2FnZScsIHRvcGljLCBwYXlsb2FkKTtcbiAgICAgICAgIH1cbiAgICAgIH1cbiAgIH0pO1xuXG4gICB0aGlzLl90aGluZ09wZXJhdGlvbiA9IGZ1bmN0aW9uKHRoaW5nTmFtZSwgb3BlcmF0aW9uLCBzdGF0ZU9iamVjdCkge1xuICAgICAgdmFyIHJjID0gbnVsbDtcblxuICAgICAgaWYgKHRoaW5nU2hhZG93cy5oYXNPd25Qcm9wZXJ0eSh0aGluZ05hbWUpKSB7XG4gICAgICAgICAvL1xuICAgICAgICAgLy8gRG9uJ3QgYWxsb3cgYSBuZXcgb3BlcmF0aW9uIGlmIGFuIGV4aXN0aW5nIG9uZSBpcyBzdGlsbCBpbiBwcm9jZXNzLlxuICAgICAgICAgLy9cbiAgICAgICAgIGlmICh0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS5wZW5kaW5nID09PSBmYWxzZSkge1xuICAgICAgICAgICAgLy9cbiAgICAgICAgICAgIC8vIFN0YXJ0aW5nIGEgbmV3IG9wZXJhdGlvblxuICAgICAgICAgICAgLy9cbiAgICAgICAgICAgIHRoaW5nU2hhZG93c1t0aGluZ05hbWVdLnBlbmRpbmcgPSB0cnVlO1xuICAgICAgICAgICAgLy9cbiAgICAgICAgICAgIC8vIElmIG5vdCBwcm92aWRlZCwgY29uc3RydWN0IGEgY2xpZW50VG9rZW4gZnJvbSB0aGUgY2xpZW50SWQgYW5kIGEgcm9sbGluZyBcbiAgICAgICAgICAgIC8vIG9wZXJhdGlvbiBjb3VudC4gIFRoZSBjbGllbnRUb2tlbiBpcyB0cmFuc21pdHRlZCBpbiBhbnkgcHVibGlzaGVkIHN0YXRlT2JqZWN0IFxuICAgICAgICAgICAgLy8gYW5kIGlzIHJldHVybmVkIHRvIHRoZSBjYWxsZXIgZm9yIGVhY2ggb3BlcmF0aW9uLiAgQXBwbGljYXRpb25zIGNhbiB1c2VcbiAgICAgICAgICAgIC8vIGNsaWVudFRva2VuIHZhbHVlcyB0byBjb3JyZWxhdGUgcmVjZWl2ZWQgcmVzcG9uc2VzIG9yIHRpbWVvdXRzIHdpdGhcbiAgICAgICAgICAgIC8vIHRoZSBvcmlnaW5hbCBvcGVyYXRpb25zLlxuICAgICAgICAgICAgLy9cbiAgICAgICAgICAgIHZhciBjbGllbnRUb2tlbjtcblxuICAgICAgICAgICAgaWYgKGlzVW5kZWZpbmVkKHN0YXRlT2JqZWN0LmNsaWVudFRva2VuKSkge1xuICAgICAgICAgICAgICAgLy9cbiAgICAgICAgICAgICAgIC8vIEFXUyBJb1QgcmVzdHJpY3RzIGNsaWVudCB0b2tlbnMgdG8gNjQgYnl0ZXMsIHNvIHVzZSBvbmx5IHRoZSBsYXN0IDQ4XG4gICAgICAgICAgICAgICAvLyBjaGFyYWN0ZXJzIG9mIHRoZSBjbGllbnQgSUQgd2hlbiBjb25zdHJ1Y3RpbmcgYSBjbGllbnQgdG9rZW4uXG4gICAgICAgICAgICAgICAvL1xuICAgICAgICAgICAgICAgdmFyIGNsaWVudElkTGVuZ3RoID0gZGV2aWNlT3B0aW9ucy5jbGllbnRJZC5sZW5ndGg7XG5cbiAgICAgICAgICAgICAgIGlmIChjbGllbnRJZExlbmd0aCA+IDQ4KSB7XG4gICAgICAgICAgICAgICAgICBjbGllbnRUb2tlbiA9IGRldmljZU9wdGlvbnMuY2xpZW50SWQuc3Vic3RyKGNsaWVudElkTGVuZ3RoIC0gNDgpICsgJy0nICsgb3BlcmF0aW9uQ291bnQrKztcbiAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICBjbGllbnRUb2tlbiA9IGRldmljZU9wdGlvbnMuY2xpZW50SWQgKyAnLScgKyBvcGVyYXRpb25Db3VudCsrO1xuICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgIGNsaWVudFRva2VuID0gc3RhdGVPYmplY3QuY2xpZW50VG9rZW47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAvL1xuICAgICAgICAgICAgLy8gUmVtZW1iZXIgdGhlIGNsaWVudCB0b2tlbiBmb3IgdGhpcyBvcGVyYXRpb247IGl0IHdpbGwgYmVcbiAgICAgICAgICAgIC8vIGRlbGV0ZWQgd2hlbiB0aGUgb3BlcmF0aW9uIGNvbXBsZXRlcyBvciB0aW1lcyBvdXQuXG4gICAgICAgICAgICAvL1xuICAgICAgICAgICAgdGhpbmdTaGFkb3dzW3RoaW5nTmFtZV0uY2xpZW50VG9rZW4gPSBjbGllbnRUb2tlbjtcblxuICAgICAgICAgICAgdmFyIHB1Ymxpc2hUb3BpYyA9IGJ1aWxkVGhpbmdTaGFkb3dUb3BpYyh0aGluZ05hbWUsXG4gICAgICAgICAgICAgICBvcGVyYXRpb24pO1xuICAgICAgICAgICAgLy9cbiAgICAgICAgICAgIC8vIFN1YnNjcmliZSB0byB0aGUgJ2FjY2VwdGVkJyBhbmQgJ3JlamVjdGVkJyBzdWItdG9waWNzIGZvciB0aGlzIGdldFxuICAgICAgICAgICAgLy8gb3BlcmF0aW9uIGFuZCBzZXQgYSB0aW1lb3V0IGJleW9uZCB3aGljaCB0aGV5IHdpbGwgYmUgdW5zdWJzY3JpYmVkIGlmIFxuICAgICAgICAgICAgLy8gbm8gbWVzc2FnZXMgaGF2ZSBiZWVuIHJlY2VpdmVkIGZvciBlaXRoZXIgb2YgdGhlbS5cbiAgICAgICAgICAgIC8vXG4gICAgICAgICAgICB0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS50aW1lb3V0ID0gc2V0VGltZW91dChcbiAgICAgICAgICAgICAgIGZ1bmN0aW9uKHRoaW5nTmFtZSwgY2xpZW50VG9rZW4pIHtcbiAgICAgICAgICAgICAgICAgIC8vXG4gICAgICAgICAgICAgICAgICAvLyBUaW1lZC1vdXQuICBVbnN1YnNjcmliZSBmcm9tIHRoZSAnYWNjZXB0ZWQnIGFuZCAncmVqZWN0ZWQnIHN1Yi10b3BpY3MgdW5sZXNzXG4gICAgICAgICAgICAgICAgICAvLyB3ZSBhcmUgcGVyc2lzdGVudGx5IHN1YnNjcmliaW5nIHRvIHRoaXMgdGhpbmcgc2hhZG93LlxuICAgICAgICAgICAgICAgICAgLy9cbiAgICAgICAgICAgICAgICAgIGlmICh0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS5wZXJzaXN0ZW50U3Vic2NyaWJlID09PSBmYWxzZSkge1xuICAgICAgICAgICAgICAgICAgICAgdGhhdC5faGFuZGxlU3Vic2NyaXB0aW9ucyh0aGluZ05hbWUsIFt7XG4gICAgICAgICAgICAgICAgICAgICAgICBvcGVyYXRpb25zOiBbb3BlcmF0aW9uXSxcbiAgICAgICAgICAgICAgICAgICAgICAgIHN0YXRpaTogWydhY2NlcHRlZCcsICdyZWplY3RlZCddXG4gICAgICAgICAgICAgICAgICAgICB9XSwgJ3Vuc3Vic2NyaWJlJyk7XG4gICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAvL1xuICAgICAgICAgICAgICAgICAgLy8gTWFyayB0aGlzIG9wZXJhdGlvbiBhcyBjb21wbGV0ZS5cbiAgICAgICAgICAgICAgICAgIC8vXG4gICAgICAgICAgICAgICAgICB0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS5wZW5kaW5nID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgICAvL1xuICAgICAgICAgICAgICAgICAgLy8gRW1pdCBhbiBldmVudCBmb3IgdGhlIHRpbWVvdXQ7IHRoZSBjbGllbnRUb2tlbiBpcyBpbmNsdWRlZCBhcyBhbiBhcmd1bWVudFxuICAgICAgICAgICAgICAgICAgLy8gc28gdGhhdCB0aGUgYXBwbGljYXRpb24gY2FuIGNvcnJlbGF0ZSB0aW1lb3V0IGV2ZW50cyB0byB0aGUgb3BlcmF0aW9uc1xuICAgICAgICAgICAgICAgICAgLy8gdGhleSBhcmUgYXNzb2NpYXRlZCB3aXRoLlxuICAgICAgICAgICAgICAgICAgLy9cbiAgICAgICAgICAgICAgICAgIHRoYXQuZW1pdCgndGltZW91dCcsIHRoaW5nTmFtZSwgY2xpZW50VG9rZW4pO1xuICAgICAgICAgICAgICAgICAgLy9cbiAgICAgICAgICAgICAgICAgIC8vIERlbGV0ZSB0aGUgdGltZW91dCBoYW5kbGUgYW5kIGNsaWVudCB0b2tlbiBmb3IgdGhpcyB0aGluZ05hbWUuXG4gICAgICAgICAgICAgICAgICAvL1xuICAgICAgICAgICAgICAgICAgZGVsZXRlIHRoaW5nU2hhZG93c1t0aGluZ05hbWVdLnRpbWVvdXQ7XG4gICAgICAgICAgICAgICAgICBkZWxldGUgdGhpbmdTaGFkb3dzW3RoaW5nTmFtZV0uY2xpZW50VG9rZW47XG4gICAgICAgICAgICAgICB9LCBvcGVyYXRpb25UaW1lb3V0LFxuICAgICAgICAgICAgICAgdGhpbmdOYW1lLCBjbGllbnRUb2tlbik7XG4gICAgICAgICAgICAvL1xuICAgICAgICAgICAgLy8gU3Vic2NyaWJlIHRvIHRoZSAnYWNjZXB0ZWQnIGFuZCAncmVqZWN0ZWQnIHN1Yi10b3BpY3MgdW5sZXNzIHdlIGFyZVxuICAgICAgICAgICAgLy8gcGVyc2lzdGVudGx5IHN1YnNjcmliaW5nLCBpbiB3aGljaCBjYXNlIHdlIGNhbiBwdWJsaXNoIHRvIHRoZSB0b3BpYyBpbW1lZGlhdGVseVxuICAgICAgICAgICAgLy8gc2luY2Ugd2UgYXJlIGFscmVhZHkgc3Vic2NyaWJlZCB0byBhbGwgYXBwbGljYWJsZSBzdWItdG9waWNzLlxuICAgICAgICAgICAgLy9cbiAgICAgICAgICAgIGlmICh0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS5wZXJzaXN0ZW50U3Vic2NyaWJlID09PSBmYWxzZSkge1xuICAgICAgICAgICAgICAgdGhpcy5faGFuZGxlU3Vic2NyaXB0aW9ucyh0aGluZ05hbWUsIFt7XG4gICAgICAgICAgICAgICAgICAgICBvcGVyYXRpb25zOiBbb3BlcmF0aW9uXSxcbiAgICAgICAgICAgICAgICAgICAgIHN0YXRpaTogWydhY2NlcHRlZCcsICdyZWplY3RlZCddLFxuICAgICAgICAgICAgICAgICAgfV0sICdzdWJzY3JpYmUnLFxuICAgICAgICAgICAgICAgICAgZnVuY3Rpb24oZXJyLCBmYWlsZWRUb3BpY3MpIHtcbiAgICAgICAgICAgICAgICAgICAgIGlmICghaXNVbmRlZmluZWQoZXJyKSB8fCAhaXNVbmRlZmluZWQoZmFpbGVkVG9waWNzKSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS53YXJuKCdmYWlsZWQgc3Vic2NyaXB0aW9uIHRvIGFjY2VwdGVkL3JlamVjdGVkIHRvcGljcycpO1xuICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAvL1xuICAgICAgICAgICAgICAgICAgICAgLy8gSWYgJ3N0YXRlT2JqZWN0JyBpcyBkZWZpbmVkLCBwdWJsaXNoIGl0IHRvIHRoZSBwdWJsaXNoIHRvcGljIGZvciB0aGlzXG4gICAgICAgICAgICAgICAgICAgICAvLyB0aGluZ05hbWUrb3BlcmF0aW9uLlxuICAgICAgICAgICAgICAgICAgICAgLy9cbiAgICAgICAgICAgICAgICAgICAgIGlmICghaXNVbmRlZmluZWQoc3RhdGVPYmplY3QpKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAvL1xuICAgICAgICAgICAgICAgICAgICAgICAgLy8gQWRkIHRoZSB2ZXJzaW9uICMgKGlmIGtub3duIGFuZCB2ZXJzaW9uaW5nIGlzIGVuYWJsZWQpIGFuZCBcbiAgICAgICAgICAgICAgICAgICAgICAgIC8vICdjbGllbnRUb2tlbicgcHJvcGVydGllcyB0byB0aGUgc3RhdGVPYmplY3QuXG4gICAgICAgICAgICAgICAgICAgICAgICAvL1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCFpc1VuZGVmaW5lZCh0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS52ZXJzaW9uKSAmJlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhpbmdTaGFkb3dzW3RoaW5nTmFtZV0uZW5hYmxlVmVyc2lvbmluZykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgc3RhdGVPYmplY3QudmVyc2lvbiA9IHRoaW5nU2hhZG93c1t0aGluZ05hbWVdLnZlcnNpb247XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICBzdGF0ZU9iamVjdC5jbGllbnRUb2tlbiA9IGNsaWVudFRva2VuO1xuXG4gICAgICAgICAgICAgICAgICAgICAgICBkZXZpY2UucHVibGlzaChwdWJsaXNoVG9waWMsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICBKU09OLnN0cmluZ2lmeShzdGF0ZU9iamVjdCksIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHFvczogdGhpbmdTaGFkb3dzW3RoaW5nTmFtZV0ucW9zXG4gICAgICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICghKGlzVW5kZWZpbmVkKHRoaW5nU2hhZG93c1t0aGluZ05hbWVdKSkgJiZcbiAgICAgICAgICAgICAgICAgICAgICAgICAgIHRoaW5nU2hhZG93c1t0aGluZ05hbWVdLmRlYnVnID09PSB0cnVlKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZygncHVibGlzaGluZyBcXCcnICsgSlNPTi5zdHJpbmdpZnkoc3RhdGVPYmplY3QpICtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICcgb24gXFwnJyArIHB1Ymxpc2hUb3BpYyArICdcXCcnKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgIC8vXG4gICAgICAgICAgICAgICAvLyBBZGQgdGhlIHZlcnNpb24gIyAoaWYga25vd24gYW5kIHZlcnNpb25pbmcgaXMgZW5hYmxlZCkgYW5kIFxuICAgICAgICAgICAgICAgLy8gJ2NsaWVudFRva2VuJyBwcm9wZXJ0aWVzIHRvIHRoZSBzdGF0ZU9iamVjdC5cbiAgICAgICAgICAgICAgIC8vXG4gICAgICAgICAgICAgICBpZiAoIWlzVW5kZWZpbmVkKHRoaW5nU2hhZG93c1t0aGluZ05hbWVdLnZlcnNpb24pICYmXG4gICAgICAgICAgICAgICAgICB0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS5lbmFibGVWZXJzaW9uaW5nKSB7XG4gICAgICAgICAgICAgICAgICBzdGF0ZU9iamVjdC52ZXJzaW9uID0gdGhpbmdTaGFkb3dzW3RoaW5nTmFtZV0udmVyc2lvbjtcbiAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgIHN0YXRlT2JqZWN0LmNsaWVudFRva2VuID0gY2xpZW50VG9rZW47XG5cbiAgICAgICAgICAgICAgIGRldmljZS5wdWJsaXNoKHB1Ymxpc2hUb3BpYyxcbiAgICAgICAgICAgICAgICAgIEpTT04uc3RyaW5naWZ5KHN0YXRlT2JqZWN0KSwge1xuICAgICAgICAgICAgICAgICAgICAgcW9zOiB0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS5xb3NcbiAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgaWYgKHRoaW5nU2hhZG93c1t0aGluZ05hbWVdLmRlYnVnID09PSB0cnVlKSB7XG4gICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZygncHVibGlzaGluZyBcXCcnICsgSlNPTi5zdHJpbmdpZnkoc3RhdGVPYmplY3QpICtcbiAgICAgICAgICAgICAgICAgICAgICcgb24gXFwnJyArIHB1Ymxpc2hUb3BpYyArICdcXCcnKTtcbiAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJjID0gY2xpZW50VG9rZW47IC8vIHJldHVybiB0aGUgY2xpZW50VG9rZW4gdG8gdGhlIGNhbGxlclxuICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGlmIChkZXZpY2VPcHRpb25zLmRlYnVnID09PSB0cnVlKSB7XG4gICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKG9wZXJhdGlvbiArICcgc3RpbGwgaW4gcHJvZ3Jlc3Mgb24gdGhpbmc6ICcsIHRoaW5nTmFtZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAgaWYgKGRldmljZU9wdGlvbnMuZGVidWcgPT09IHRydWUpIHtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ2F0dGVtcHRpbmcgdG8gJyArIG9wZXJhdGlvbiArICcgdW5rbm93biB0aGluZzogJywgdGhpbmdOYW1lKTtcbiAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiByYztcbiAgIH07XG5cbiAgIHRoaXMucmVnaXN0ZXIgPSBmdW5jdGlvbih0aGluZ05hbWUsIG9wdGlvbnMsIGNhbGxiYWNrKSB7XG4gICAgICBpZiAoIXRoaW5nU2hhZG93cy5oYXNPd25Qcm9wZXJ0eSh0aGluZ05hbWUpKSB7XG4gICAgICAgICAvL1xuICAgICAgICAgLy8gSW5pdGlhbGl6ZSB0aGUgcmVnaXN0cmF0aW9uIGVudHJ5IGZvciB0aGlzIHRoaW5nOyBiZWNhdXNlIHRoZSB2ZXJzaW9uICMgaXMgXG4gICAgICAgICAvLyBub3QgeWV0IGtub3duLCBkbyBub3QgYWRkIHRoZSBwcm9wZXJ0eSBmb3IgaXQgeWV0LiBUaGUgdmVyc2lvbiBudW1iZXIgXG4gICAgICAgICAvLyBwcm9wZXJ0eSB3aWxsIGJlIGFkZGVkIGFmdGVyIHRoZSBmaXJzdCBhY2NlcHRlZCB1cGRhdGUgZnJvbSBBV1MgSW9ULlxuICAgICAgICAgLy9cbiAgICAgICAgIHZhciBpZ25vcmVEZWx0YXMgPSBmYWxzZTtcbiAgICAgICAgIHZhciB0b3BpY1NwZWNzID0gW107XG4gICAgICAgICB0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXSA9IHtcbiAgICAgICAgICAgIHBlcnNpc3RlbnRTdWJzY3JpYmU6IHRydWUsXG4gICAgICAgICAgICBkZWJ1ZzogZmFsc2UsXG4gICAgICAgICAgICBkaXNjYXJkU3RhbGU6IHRydWUsXG4gICAgICAgICAgICBlbmFibGVWZXJzaW9uaW5nOiB0cnVlLFxuICAgICAgICAgICAgcW9zOiAwLFxuICAgICAgICAgICAgcGVuZGluZzogdHJ1ZVxuICAgICAgICAgfTtcblxuICAgICAgICAgaWYgKCFpc1VuZGVmaW5lZChvcHRpb25zKSkge1xuICAgICAgICAgICAgaWYgKCFpc1VuZGVmaW5lZChvcHRpb25zLmlnbm9yZURlbHRhcykpIHtcbiAgICAgICAgICAgICAgIGlnbm9yZURlbHRhcyA9IG9wdGlvbnMuaWdub3JlRGVsdGFzO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKCFpc1VuZGVmaW5lZChvcHRpb25zLnBlcnNpc3RlbnRTdWJzY3JpYmUpKSB7XG4gICAgICAgICAgICAgICB0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS5wZXJzaXN0ZW50U3Vic2NyaWJlID0gb3B0aW9ucy5wZXJzaXN0ZW50U3Vic2NyaWJlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKCFpc1VuZGVmaW5lZChvcHRpb25zLmRlYnVnKSkge1xuICAgICAgICAgICAgICAgdGhpbmdTaGFkb3dzW3RoaW5nTmFtZV0uZGVidWcgPSBvcHRpb25zLmRlYnVnO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKCFpc1VuZGVmaW5lZChvcHRpb25zLmRpc2NhcmRTdGFsZSkpIHtcbiAgICAgICAgICAgICAgIHRoaW5nU2hhZG93c1t0aGluZ05hbWVdLmRpc2NhcmRTdGFsZSA9IG9wdGlvbnMuZGlzY2FyZFN0YWxlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKCFpc1VuZGVmaW5lZChvcHRpb25zLmVuYWJsZVZlcnNpb25pbmcpKSB7XG4gICAgICAgICAgICAgICB0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS5lbmFibGVWZXJzaW9uaW5nID0gb3B0aW9ucy5lbmFibGVWZXJzaW9uaW5nO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKCFpc1VuZGVmaW5lZChvcHRpb25zLnFvcykpIHtcbiAgICAgICAgICAgICAgIHRoaW5nU2hhZG93c1t0aGluZ05hbWVdLnFvcyA9IG9wdGlvbnMucW9zO1xuICAgICAgICAgICAgfVxuICAgICAgICAgfVxuICAgICAgICAgLy9cbiAgICAgICAgIC8vIEFsd2F5cyBsaXN0ZW4gZm9yIGRlbHRhcyB1bmxlc3MgcmVxdWVzdGVkIG90aGVyd2lzZS5cbiAgICAgICAgIC8vXG4gICAgICAgICBpZiAoaWdub3JlRGVsdGFzID09PSBmYWxzZSkge1xuICAgICAgICAgICAgdG9waWNTcGVjcy5wdXNoKHtcbiAgICAgICAgICAgICAgIG9wZXJhdGlvbnM6IFsndXBkYXRlJ10sXG4gICAgICAgICAgICAgICBzdGF0aWk6IFsnZGVsdGEnXVxuICAgICAgICAgICAgfSk7XG4gICAgICAgICB9XG4gICAgICAgICAvL1xuICAgICAgICAgLy8gSWYgd2UgYXJlIHBlcnNpc3RlbnRseSBzdWJzY3JpYmluZywgd2Ugc3Vic2NyaWJlIHRvIGV2ZXJ5dGhpbmcgd2UgY291bGQgZXZlclxuICAgICAgICAgLy8gcG9zc2libHkgYmUgaW50ZXJlc3RlZCBpbi4gIFRoaXMgd2lsbCBwcm92aWRlIHVzIHRoZSBhYmlsaXR5IHRvIHB1Ymxpc2hcbiAgICAgICAgIC8vIHdpdGhvdXQgd2FpdGluZyBhdCB0aGUgY29zdCBvZiBwb3RlbnRpYWxseSBpbmNyZWFzZWQgaXJyZWxldmFudCB0cmFmZmljXG4gICAgICAgICAvLyB3aGljaCB0aGUgYXBwbGljYXRpb24gd2lsbCBuZWVkIHRvIGZpbHRlciBvdXQuXG4gICAgICAgICAvL1xuICAgICAgICAgaWYgKHRoaW5nU2hhZG93c1t0aGluZ05hbWVdLnBlcnNpc3RlbnRTdWJzY3JpYmUgPT09IHRydWUpIHtcbiAgICAgICAgICAgIHRvcGljU3BlY3MucHVzaCh7XG4gICAgICAgICAgICAgICBvcGVyYXRpb25zOiBbJ3VwZGF0ZScsICdnZXQnLCAnZGVsZXRlJ10sXG4gICAgICAgICAgICAgICBzdGF0aWk6IFsnYWNjZXB0ZWQnLCAncmVqZWN0ZWQnXVxuICAgICAgICAgICAgfSk7XG4gICAgICAgICB9XG5cbiAgICAgICAgIGlmICh0b3BpY1NwZWNzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgIHRoaXMuX2hhbmRsZVN1YnNjcmlwdGlvbnModGhpbmdOYW1lLCB0b3BpY1NwZWNzLCAnc3Vic2NyaWJlJywgZnVuY3Rpb24oZXJyLCBmYWlsZWRUb3BpY3MpIHtcbiAgICAgICAgICAgICAgIGlmIChpc1VuZGVmaW5lZChlcnIpICYmIGlzVW5kZWZpbmVkKGZhaWxlZFRvcGljcykpIHtcbiAgICAgICAgICAgICAgICAgIHRoaW5nU2hhZG93c1t0aGluZ05hbWVdLnBlbmRpbmcgPSBmYWxzZTtcbiAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgIGlmICghaXNVbmRlZmluZWQoY2FsbGJhY2spKSB7XG4gICAgICAgICAgICAgICAgICBjYWxsYmFjayhlcnIsIGZhaWxlZFRvcGljcyk7XG4gICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS5wZW5kaW5nID0gZmFsc2U7XG4gICAgICAgICAgICBpZiAoIWlzVW5kZWZpbmVkKGNhbGxiYWNrKSkge1xuICAgICAgICAgICAgICAgY2FsbGJhY2soKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgIH1cblxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgIGlmIChkZXZpY2VPcHRpb25zLmRlYnVnID09PSB0cnVlKSB7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCd0aGluZyBhbHJlYWR5IHJlZ2lzdGVyZWQ6ICcsIHRoaW5nTmFtZSk7XG4gICAgICAgICB9XG4gICAgICB9XG4gICB9O1xuXG4gICB0aGlzLnVucmVnaXN0ZXIgPSBmdW5jdGlvbih0aGluZ05hbWUpIHtcbiAgICAgIGlmICh0aGluZ1NoYWRvd3MuaGFzT3duUHJvcGVydHkodGhpbmdOYW1lKSkge1xuICAgICAgICAgdmFyIHRvcGljU3BlY3MgPSBbXTtcblxuICAgICAgICAgLy9cbiAgICAgICAgIC8vIElmIGFuIG9wZXJhdGlvbiBpcyBvdXRzdGFuZGluZywgaXQgd2lsbCBoYXZlIGEgdGltZW91dCBzZXQ7IHdoZW4gaXRcbiAgICAgICAgIC8vIGV4cGlyZXMgYW55IGFjY2VwdC9yZWplY3Qgc3ViLXRvcGljIHN1YnNjcmlwdGlvbnMgZm9yIHRoZSB0aGluZyB3aWxsIGJlIFxuICAgICAgICAgLy8gZGVsZXRlZC4gIElmIGFueSBtZXNzYWdlcyBhcnJpdmUgYWZ0ZXIgdGhlIHRoaW5nIGhhcyBiZWVuIGRlbGV0ZWQsIHRoZXlcbiAgICAgICAgIC8vIHdpbGwgc2ltcGx5IGJlIGlnbm9yZWQgYXMgaXQgbm8gbG9uZ2VyIGV4aXN0cyBpbiB0aGUgdGhpbmcgcmVnaXN0cmF0aW9ucy5cbiAgICAgICAgIC8vIFRoZSBvbmx5IHN1Yi10b3BpYyB3ZSBuZWVkIHRvIHVuc3Vic2NyaWJlIGZyb20gaXMgdGhlIGRlbHRhIHN1Yi10b3BpYyxcbiAgICAgICAgIC8vIHdoaWNoIGlzIGFsd2F5cyBhY3RpdmUuXG4gICAgICAgICAvL1xuICAgICAgICAgdG9waWNTcGVjcy5wdXNoKHtcbiAgICAgICAgICAgIG9wZXJhdGlvbnM6IFsndXBkYXRlJ10sXG4gICAgICAgICAgICBzdGF0aWk6IFsnZGVsdGEnXVxuICAgICAgICAgfSk7XG4gICAgICAgICAvL1xuICAgICAgICAgLy8gSWYgd2UgYXJlIHBlcnNpc3RlbnRseSBzdWJzY3JpYmluZywgd2Ugc3Vic2NyaWJlIHRvIGV2ZXJ5dGhpbmcgd2UgY291bGQgZXZlclxuICAgICAgICAgLy8gcG9zc2libHkgYmUgaW50ZXJlc3RlZCBpbjsgdGhpcyBtZWFucyB0aGF0IHdoZW4gaXQncyB0aW1lIHRvIHVucmVnaXN0ZXJcbiAgICAgICAgIC8vIGludGVyZXN0IGluIGEgdGhpbmcsIHdlIG5lZWQgdG8gdW5zdWJzY3JpYmUgZnJvbSBhbGwgb2YgdGhlc2UgdG9waWNzLlxuICAgICAgICAgLy9cbiAgICAgICAgIGlmICh0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS5wZXJzaXN0ZW50U3Vic2NyaWJlID09PSB0cnVlKSB7XG4gICAgICAgICAgICB0b3BpY1NwZWNzLnB1c2goe1xuICAgICAgICAgICAgICAgb3BlcmF0aW9uczogWyd1cGRhdGUnLCAnZ2V0JywgJ2RlbGV0ZSddLFxuICAgICAgICAgICAgICAgc3RhdGlpOiBbJ2FjY2VwdGVkJywgJ3JlamVjdGVkJ11cbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgfVxuXG4gICAgICAgICB0aGlzLl9oYW5kbGVTdWJzY3JpcHRpb25zKHRoaW5nTmFtZSwgdG9waWNTcGVjcywgJ3Vuc3Vic2NyaWJlJyk7XG5cbiAgICAgICAgIC8vXG4gICAgICAgICAvLyBEZWxldGUgYW55IHBlbmRpbmcgdGltZW91dFxuICAgICAgICAgLy9cbiAgICAgICAgIGlmICghaXNVbmRlZmluZWQodGhpbmdTaGFkb3dzW3RoaW5nTmFtZV0udGltZW91dCkpIHtcbiAgICAgICAgICAgIGNsZWFyVGltZW91dCh0aGluZ1NoYWRvd3NbdGhpbmdOYW1lXS50aW1lb3V0KTtcbiAgICAgICAgIH1cbiAgICAgICAgIC8vXG4gICAgICAgICAvLyBEZWxldGUgdGhlIHRoaW5nIGZyb20gdGhlIFRoaW5nIHJlZ2lzdHJhdGlvbnMuXG4gICAgICAgICAvL1xuICAgICAgICAgZGVsZXRlIHRoaW5nU2hhZG93c1t0aGluZ05hbWVdO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgIGlmIChkZXZpY2VPcHRpb25zLmRlYnVnID09PSB0cnVlKSB7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdhdHRlbXB0aW5nIHRvIHVucmVnaXN0ZXIgdW5rbm93biB0aGluZzogJywgdGhpbmdOYW1lKTtcbiAgICAgICAgIH1cbiAgICAgIH1cbiAgIH07XG5cbiAgIC8vXG4gICAvLyBQZXJmb3JtIGFuIHVwZGF0ZSBvcGVyYXRpb24gb24gdGhlIGdpdmVuIHRoaW5nIHNoYWRvdy5cbiAgIC8vXG4gICB0aGlzLnVwZGF0ZSA9IGZ1bmN0aW9uKHRoaW5nTmFtZSwgc3RhdGVPYmplY3QpIHtcbiAgICAgIHZhciByYyA9IG51bGw7XG4gICAgICAvL1xuICAgICAgLy8gVmVyaWZ5IHRoYXQgdGhlIG1lc3NhZ2UgZG9lcyBub3QgY29udGFpbiBhIHByb3BlcnR5IG5hbWVkICd2ZXJzaW9uJyxcbiAgICAgIC8vIGFzIHRoZXNlIHByb3BlcnR5IGlzIHJlc2VydmVkIGZvciB1c2Ugd2l0aGluIHRoaXMgY2xhc3MuXG4gICAgICAvL1xuICAgICAgaWYgKGlzVW5kZWZpbmVkKHN0YXRlT2JqZWN0LnZlcnNpb24pKSB7XG4gICAgICAgICByYyA9IHRoYXQuX3RoaW5nT3BlcmF0aW9uKHRoaW5nTmFtZSwgJ3VwZGF0ZScsIHN0YXRlT2JqZWN0KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgICBjb25zb2xlLmVycm9yKCdtZXNzYWdlIGNhblxcJ3QgY29udGFpbiBcXCd2ZXJzaW9uXFwnIHByb3BlcnR5Jyk7XG4gICAgICB9XG4gICAgICByZXR1cm4gcmM7XG4gICB9O1xuXG4gICAvL1xuICAgLy8gUGVyZm9ybSBhIGdldCBvcGVyYXRpb24gb24gdGhlIGdpdmVuIHRoaW5nIHNoYWRvdzsgYWxsb3cgdGhlIHVzZXJcbiAgIC8vIHRvIHNwZWNpZnkgdGhlaXIgb3duIGNsaWVudCB0b2tlbiBpZiB0aGV5IGRvbid0IHdhbnQgdG8gdXNlIHRoZVxuICAgLy8gZGVmYXVsdC5cbiAgIC8vXG4gICB0aGlzLmdldCA9IGZ1bmN0aW9uKHRoaW5nTmFtZSwgY2xpZW50VG9rZW4pIHtcbiAgICAgIHZhciBzdGF0ZU9iamVjdCA9IHt9O1xuICAgICAgaWYgKCFpc1VuZGVmaW5lZChjbGllbnRUb2tlbikpIHtcbiAgICAgICAgIHN0YXRlT2JqZWN0LmNsaWVudFRva2VuID0gY2xpZW50VG9rZW47XG4gICAgICB9XG4gICAgICByZXR1cm4gdGhhdC5fdGhpbmdPcGVyYXRpb24odGhpbmdOYW1lLCAnZ2V0Jywgc3RhdGVPYmplY3QpO1xuICAgfTtcblxuICAgLy9cbiAgIC8vIFBlcmZvcm0gYSBkZWxldGUgb3BlcmF0aW9uIG9uIHRoZSBnaXZlbiB0aGluZyBzaGFkb3cuXG4gICAvL1xuICAgdGhpcy5kZWxldGUgPSBmdW5jdGlvbih0aGluZ05hbWUsIGNsaWVudFRva2VuKSB7XG4gICAgICB2YXIgc3RhdGVPYmplY3QgPSB7fTtcbiAgICAgIGlmICghaXNVbmRlZmluZWQoY2xpZW50VG9rZW4pKSB7XG4gICAgICAgICBzdGF0ZU9iamVjdC5jbGllbnRUb2tlbiA9IGNsaWVudFRva2VuO1xuICAgICAgfVxuICAgICAgcmV0dXJuIHRoYXQuX3RoaW5nT3BlcmF0aW9uKHRoaW5nTmFtZSwgJ2RlbGV0ZScsIHN0YXRlT2JqZWN0KTtcbiAgIH07XG4gICAvL1xuICAgLy8gUHVibGlzaCBvbiBub24tdGhpbmcgdG9waWNzLlxuICAgLy9cbiAgIHRoaXMucHVibGlzaCA9IGZ1bmN0aW9uKHRvcGljLCBtZXNzYWdlLCBvcHRpb25zLCBjYWxsYmFjaykge1xuICAgICAgaWYgKCFpc1Jlc2VydmVkVG9waWModG9waWMpKSB7XG4gICAgICAgICBkZXZpY2UucHVibGlzaCh0b3BpYywgbWVzc2FnZSwgb3B0aW9ucywgY2FsbGJhY2spO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgIHRocm93ICgnY2Fubm90IHB1Ymxpc2ggdG8gcmVzZXJ2ZWQgdG9waWMgXFwnJyArIHRvcGljICsgJ1xcJycpO1xuICAgICAgfVxuICAgfTtcblxuICAgLy9cbiAgIC8vIFN1YnNjcmliZSB0byBub24tdGhpbmcgdG9waWNzLlxuICAgLy9cbiAgIHRoaXMuc3Vic2NyaWJlID0gZnVuY3Rpb24odG9waWMsIG9wdGlvbnMsIGNhbGxiYWNrKSB7XG4gICAgICBpZiAoIWlzUmVzZXJ2ZWRUb3BpYyh0b3BpYykpIHtcbiAgICAgICAgIGRldmljZS5zdWJzY3JpYmUodG9waWMsIG9wdGlvbnMsIGNhbGxiYWNrKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgICB0aHJvdyAoJ2Nhbm5vdCBzdWJzY3JpYmUgdG8gcmVzZXJ2ZWQgdG9waWMgXFwnJyArIHRvcGljICsgJ1xcJycpO1xuICAgICAgfVxuICAgfTtcbiAgIC8vXG4gICAvLyBVbnN1YnNjcmliZSBmcm9tIG5vbi10aGluZyB0b3BpY3MuXG4gICAvL1xuICAgdGhpcy51bnN1YnNjcmliZSA9IGZ1bmN0aW9uKHRvcGljLCBjYWxsYmFjaykge1xuICAgICAgaWYgKCFpc1Jlc2VydmVkVG9waWModG9waWMpKSB7XG4gICAgICAgICBkZXZpY2UudW5zdWJzY3JpYmUodG9waWMsIGNhbGxiYWNrKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgICB0aHJvdyAoJ2Nhbm5vdCB1bnN1YnNjcmliZSBmcm9tIHJlc2VydmVkIHRvcGljIFxcJycgKyB0b3BpYyArICdcXCcnKTtcbiAgICAgIH1cbiAgIH07XG4gICAvL1xuICAgLy8gQ2xvc2UgdGhlIGRldmljZSBjb25uZWN0aW9uOyB0aGlzIHdpbGwgYmUgcGFzc2VkIHRocm91Z2ggdG9cbiAgIC8vIHRoZSBkZXZpY2UgY2xhc3MuXG4gICAvL1xuICAgdGhpcy5lbmQgPSBmdW5jdGlvbihmb3JjZSwgY2FsbGJhY2spIHtcbiAgICAgIGRldmljZS5lbmQoZm9yY2UsIGNhbGxiYWNrKTtcbiAgIH07XG4gICAvL1xuICAgLy8gQ2FsbCB0aGlzIGZ1bmN0aW9uIHRvIHVwZGF0ZSB0aGUgY3JlZGVudGlhbHMgdXNlZCB3aGVuXG4gICAvLyBjb25uZWN0aW5nIHZpYSBXZWJTb2NrZXQvU2lnVjQ7IHRoaXMgd2lsbCBiZSBwYXNzZWQgdGhyb3VnaFxuICAgLy8gdG8gdGhlIGRldmljZSBjbGFzcy5cbiAgIC8vXG4gICB0aGlzLnVwZGF0ZVdlYlNvY2tldENyZWRlbnRpYWxzID0gZnVuY3Rpb24oYWNjZXNzS2V5SWQsIHNlY3JldEtleSwgc2Vzc2lvblRva2VuLCBleHBpcmF0aW9uKSB7XG4gICAgICBkZXZpY2UudXBkYXRlV2ViU29ja2V0Q3JlZGVudGlhbHMoYWNjZXNzS2V5SWQsIHNlY3JldEtleSwgc2Vzc2lvblRva2VuLCBleHBpcmF0aW9uKTtcbiAgIH07XG5cbiAgIC8vXG4gICAvLyBUaGlzIGlzIGFuIHVucHVibGlzaGVkIEFQSSB1c2VkIGZvciB0ZXN0aW5nLlxuICAgLy9cbiAgIHRoaXMuc2V0Q29ubmVjdGlvblN0YXR1cyA9IGZ1bmN0aW9uKGNvbm5lY3Rpb25TdGF0dXMpIHtcbiAgICAgIGNvbm5lY3RlZCA9IGNvbm5lY3Rpb25TdGF0dXM7XG4gICB9O1xuICAgZXZlbnRzLkV2ZW50RW1pdHRlci5jYWxsKHRoaXMpO1xufVxuXG4vL1xuLy8gQWxsb3cgaW5zdGFuY2VzIHRvIGxpc3RlbiBpbiBvbiBldmVudHMgdGhhdCB3ZSBwcm9kdWNlIGZvciB0aGVtXG4vL1xuaW5oZXJpdHMoVGhpbmdTaGFkb3dzQ2xpZW50LCBldmVudHMuRXZlbnRFbWl0dGVyKTtcblxuXG52YXIgRGV2aWNlQ2xpZW50ID0gZnVuY3Rpb24ob3B0aW9ucykge1xuICAgaWYgKCEodGhpcyBpbnN0YW5jZW9mIERldmljZUNsaWVudCkpIHtcbiAgICAgIHJldHVybiBuZXcgRGV2aWNlQ2xpZW50KG9wdGlvbnMpO1xuICAgfVxuXG4gICB0aGlzLnN1YnNjcmlwdGlvbnMgPSB7fTtcbiAgIHJldHVybiB0aGlzO1xufVxuaW5oZXJpdHMoRGV2aWNlQ2xpZW50LCBldmVudHMuRXZlbnRFbWl0dGVyKTtcblxuRGV2aWNlQ2xpZW50LnByb3RvdHlwZS5oYW5kbGVNZXNzYWdlID0gZnVuY3Rpb24obWVzc2FnZSkge1xuICB0aGlzLmVtaXQoJ21lc3NhZ2UnLG1lc3NhZ2UudG9waWMsSlNPTi5zdHJpbmdpZnkobWVzc2FnZS5wYXlsb2FkKSk7XG59XG5cbkRldmljZUNsaWVudC5wcm90b3R5cGUuc3Vic2NyaWJlID0gZnVuY3Rpb24odG9waWNzLG9wdGlvbnMsY2FsbGJhY2spIHtcbiAgZm9yKHZhciBpIGluIHRvcGljcykge1xuICAgIHZhciB0b3BpYyA9IHRvcGljc1tpXTtcbiAgICBpZighdGhpcy5zdWJzY3JpcHRpb25zW3RvcGljXSkge1xuICAgICAgTm9vZGwuUHViU3ViLnN1YnNjcmliZSh0b3BpYyx0aGlzLmhhbmRsZU1lc3NhZ2UuYmluZCh0aGlzKSk7XG4gICAgICBcbiAgICAgIGlmKCF0aGlzLnN1YnNjcmlwdGlvbnNbdG9waWNdKSB0aGlzLnN1YnNjcmlwdGlvbnNbdG9waWNdID0gMDtcbiAgICAgIHRoaXMuc3Vic2NyaXB0aW9uc1t0b3BpY10rKzsgIFxuICAgIH1cbiAgfVxuICBjYWxsYmFjayhudWxsLFtdKTtcbn1cblxuRGV2aWNlQ2xpZW50LnByb3RvdHlwZS51bnN1YnNjcmliZSA9IGZ1bmN0aW9uKHRvcGljcykge1xuICBmb3IodmFyIGkgaW4gdG9waWNzKSB7XG4gICAgdmFyIHRvcGljID0gdG9waWNzW2ldO1xuXG4gICAgaWYoIXRoaXMuc3Vic2NyaXB0aW9uc1t0b3BpY10pIGNvbnRpbnVlO1xuICAgIHRoaXMuc3Vic2NyaXB0aW9uc1t0b3BpY10tLTtcbiAgICBpZih0aGlzLnN1YnNjcmlwdGlvbnNbdG9waWNdID09PSAwKSB7XG4gICAgICBOb29kbC5QdWJTdWIudW5zdWJzY3JpYmUodG9waWMpO1xuICAgIH1cbiAgfVxufVxuXG5EZXZpY2VDbGllbnQucHJvdG90eXBlLnB1Ymxpc2ggPSBmdW5jdGlvbih0b3BpYyxtZXNzYWdlLG9wdGlvbnMpIHtcbiAgTm9vZGwuUHViU3ViLnB1Ymxpc2godG9waWMsSlNPTi5wYXJzZShtZXNzYWdlKSk7XG59XG5cbmRldmljZU1vZHVsZS5EZXZpY2VDbGllbnQgPSBEZXZpY2VDbGllbnQ7XG5cbnZhciBUaGluZ1N0YXRlID0gZnVuY3Rpb24oY2xpZW50SWQpIHtcbiAgdmFyIF90aGlzID0gdGhpcztcbiAgdGhpcy5jYWxsYmFja3MgPSBbXTtcbiAgdGhpcy5oYW5kbGVycyA9IHt9O1xuXG4gIHRoaXMuY2xpZW50ID0gbmV3IFRoaW5nU2hhZG93c0NsaWVudCh7Y2xpZW50SWQ6Y2xpZW50SWR9LHt9KTtcblxuICB0aGlzLmNsaWVudC5vbignc3RhdHVzJyxmdW5jdGlvbih0aGluZ05hbWUsIHN0YXQsIGNsaWVudFRva2VuLCBzdGF0ZU9iamVjdCkge1xuICAgLy8gICAgICAgICAgICAgY29uc29sZS5sb2coJ3JlY2VpdmVkICcrc3RhdCsnIG9uICcrdGhpbmdOYW1lKyc6ICcrXG4gICAgIC8vICAgICAgICAgICAgICAgICAgICAgICBKU09OLnN0cmluZ2lmeShzdGF0ZU9iamVjdCkpO1xuXG4gICAgdmFyIGNiID0gX3RoaXMuY2FsbGJhY2tzW2NsaWVudFRva2VuXTtcbiAgICBpZihjYiAmJiBzdGF0ID09PSBcImFjY2VwdGVkXCIpIHtcbiAgICAgIHZhciBkZXNpcmVkU3RhdGUgPSBzdGF0ZU9iamVjdC5zdGF0ZS5kZXNpcmVkO1xuICAgICAgY2IoZGVzaXJlZFN0YXRlKTtcbiAgICAgIGRlbGV0ZSBfdGhpcy5jYWxsYmFja3NbY2xpZW50VG9rZW5dO1xuICAgIH1cbiAgfSk7XG5cbiAgdGhpcy5jbGllbnQub24oJ2RlbHRhJyxmdW5jdGlvbih0aGluZ05hbWUsIHN0YXRlT2JqZWN0KSB7XG4gICAgdmFyIGhhbmRsZXJzID0gX3RoaXMuaGFuZGxlcnNbdGhpbmdOYW1lXTtcbiAgICBmb3IodmFyIGkgPSAwOyBpIDwgaGFuZGxlcnMubGVuZ3RoOyBpKyspIHtcbiAgICAgIGhhbmRsZXJzW2ldLm9uRGVsdGEoc3RhdGVPYmplY3Quc3RhdGUpO1xuICAgIH1cbiAgIC8vICAgIGNvbnNvbGUubG9nKCdyZWNlaXZlZCBkZWx0YSBvbiAnK3RoaW5nTmFtZSsnOiAnK1xuICAgICAvLyAgICAgICAgICAgICAgSlNPTi5zdHJpbmdpZnkoc3RhdGVPYmplY3QpKTtcbiAgICAgICAgICAgICAgICAgICBcbiAgfSk7XG59XG5cblRoaW5nU3RhdGUucHJvdG90eXBlLnJlZ2lzdGVyID0gZnVuY3Rpb24obmFtZSxoYW5kbGVycykge1xuICB2YXIgX3RoaXMgPSB0aGlzO1xuXG4gIHRoaXMuY2xpZW50LnJlZ2lzdGVyKG5hbWUse30sZnVuY3Rpb24oKSB7XG4gICAgaWYoIV90aGlzLmhhbmRsZXJzW25hbWVdKSBfdGhpcy5oYW5kbGVyc1tuYW1lXSA9IFtdO1xuICAgIGlmKF90aGlzLmhhbmRsZXJzW25hbWVdLmluZGV4T2YoaGFuZGxlcnMpID09PSAtMSlcbiAgICAgIF90aGlzLmhhbmRsZXJzW25hbWVdLnB1c2goaGFuZGxlcnMpO1xuXG4gICAgaGFuZGxlcnMub25SZWdpc3RlcmVkKCk7XG4gIH0pO1xufVxuXG5UaGluZ1N0YXRlLnByb3RvdHlwZS51bnJlZ2lzdGVyID0gZnVuY3Rpb24obmFtZSxoYW5kbGVycykge1xuICBpZighdGhpcy5oYW5kbGVyc1tuYW1lXSkgcmV0dXJuO1xuICB2YXIgaWR4ID0gdGhpcy5oYW5kbGVyc1tuYW1lXS5pbmRleE9mKGhhbmRsZXJzKSA7XG4gIGlmKGlkeCAhPT0gLTEpIHtcbiAgICB0aGlzLmhhbmRsZXJzW25hbWVdLnNwbGljZShpZHgsMSk7XG4gIH1cbiAgaWYodGhpcy5oYW5kbGVyc1tuYW1lXS5sZW5ndGggPT09IDApIHtcbiAgICB0aGlzLmNsaWVudC51bnJlZ2lzdGVyKG5hbWUpO1xuICB9XG59XG5cblRoaW5nU3RhdGUucHJvdG90eXBlLnVwZGF0ZSA9IGZ1bmN0aW9uKG5hbWUsc3RhdGUpIHtcbiAgdmFyIF9zdGF0ZSA9IHtcInN0YXRlXCI6e1wiZGVzaXJlZFwiOnN0YXRlfX07XG4gIHRoaXMuY2xpZW50LnVwZGF0ZShuYW1lLF9zdGF0ZSk7XG59XG5cblRoaW5nU3RhdGUucHJvdG90eXBlLmdldCA9IGZ1bmN0aW9uKG5hbWUsY2FsbGJhY2spIHtcbiAgdmFyIGNsaWVudFRva2VuID0gdGhpcy5jbGllbnQuZ2V0KG5hbWUpO1xuICB0aGlzLmNhbGxiYWNrc1tjbGllbnRUb2tlbl0gPSBjYWxsYmFjaztcbn1cblxuVGhpbmdTdGF0ZS5pbnN0YW5jZSA9IG5ldyBUaGluZ1N0YXRlKCd3dXAnKTtcblxubW9kdWxlLmV4cG9ydHMgPSBUaGluZ1N0YXRlOyIsIlwidXNlIHN0cmljdFwiO1xuXG52YXIgRXZlbnRFbWl0dGVyID0gcmVxdWlyZSgnZXZlbnRzJykuRXZlbnRFbWl0dGVyO1xuXG5mdW5jdGlvbiBVc2VyTWFuYWdlbWVudCgpIHtcbiAgICB2YXIgX3RoaXMgPSB0aGlzO1xuXG4gICAgdGhpcy5zZXNzaW9uU3RhdGUgPSBVc2VyTWFuYWdlbWVudC5TZXNzaW9uU3RhdGUuSW52YWxpZDtcbiAgICB0aGlzLmV2ZW50cyA9IG5ldyBFdmVudEVtaXR0ZXIoKTtcbn1cblxuVXNlck1hbmFnZW1lbnQucHJvdG90eXBlLlNlc3Npb25TdGF0ZSA9IFVzZXJNYW5hZ2VtZW50LlNlc3Npb25TdGF0ZSA9IHtcbiAgICBWYWxpZDogJ1ZhbGlkJyxcbiAgICBJbnZhbGlkOiAnSW52YWxpZCcsXG4gICAgUGVuZGluZzogJ1BlbmRpbmcnLFxufTtcblxuVXNlck1hbmFnZW1lbnQucHJvdG90eXBlLmdldFNlc3Npb25TdGF0ZSA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLnNlc3Npb25TdGF0ZTtcbn1cblxuVXNlck1hbmFnZW1lbnQucHJvdG90eXBlLmF0dGVtcHRDYWNoZWRTaWduSW4gPSBmdW5jdGlvbigpIHtcbiAgICB2YXIgX3RoaXMgPSB0aGlzO1xuXG4gICAgdGhpcy5zZXNzaW9uU3RhdGUgPSBVc2VyTWFuYWdlbWVudC5TZXNzaW9uU3RhdGUuUGVuZGluZztcbiAgICB0aGlzLmF0dGVtcHRTaWduSW5XaXRoQ2FjaGVkVG9rZW5zKHtcbiAgICAgICAgZmFpbHVyZTpmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIF90aGlzLmV2ZW50cy5lbWl0KCd1c2VyTWFuYWdlbWVudENhY2hlZENyZWRlbnRpYWxzTm90QXZhaWxhYmxlJyk7XG4gICAgICAgIH0sXG4gICAgICAgIHN1Y2Nlc3M6ZnVuY3Rpb24oKSB7IFxuICAgICAgICB9XG4gICAgfSkgICAgIFxufVxuXG4vKlxuVXNlck1hbmFnZW1lbnQucHJvdG90eXBlLnNldFNldHRpbmdzID0gZnVuY3Rpb24gKHNldHRpbmdzKSB7XG4gICAgdmFyIF90aGlzID0gdGhpcztcblxuICAgIHRoaXMuc2V0dGluZ3MgPSBzZXR0aW5ncztcbiAgICB0aGlzLnNlc3Npb25TdGF0ZSA9IFVzZXJNYW5hZ2VtZW50LlNlc3Npb25TdGF0ZS5QZW5kaW5nO1xuICAgIHRoaXMuYXR0ZW1wdFNpZ25JbldpdGhDYWNoZWRUb2tlbnMoe1xuICAgICAgICBmYWlsdXJlOmZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgU2VydmljZXMuZXZlbnRzLmVtaXQoJ3VzZXJNYW5hZ2VtZW50Q2FjaGVkQ3JlZGVudGlhbHNOb3RBdmFpbGFibGUnKTtcbiAgICAgICAgfSxcbiAgICAgICAgc3VjY2VzczpmdW5jdGlvbigpIHsgXG4gICAgICAgIH1cbiAgICB9KVxufSovXG5cblVzZXJNYW5hZ2VtZW50LnByb3RvdHlwZS5nZXRDcmVkZW50aWFscyA9IGZ1bmN0aW9uKHRva2VuLGFyZ3MpIHtcbiAgICB2YXIgX3RoaXMgPSB0aGlzO1xuXG4gICAgdmFyIHNldHRpbmdzID0gTm9vZGwuZ2V0UHJvamVjdFNldHRpbmdzKCk7XG5cbiAgICBBV1MuY29uZmlnLnJlZ2lvbiA9IE5vb2RsLmdldFByb2plY3RTZXR0aW5ncygpLmF3c0lvVFJlZ2lvbnx8J3VzLWVhc3QtMSc7XG4gICAgdmFyIGNyZWRzID0ge1xuICAgICAgICBJZGVudGl0eVBvb2xJZDogc2V0dGluZ3MudXNlck1hbmFnZW1lbnRBV1NJZGVudGl0eVBvb2xJZCxcbiAgICAgICAgTG9naW5zOiB7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIGNyZWRzLkxvZ2luc1snY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb20vJyArIHNldHRpbmdzLnVzZXJNYW5hZ2VtZW50QVdTVXNlclBvb2xJZF0gPSB0b2tlbjtcblxuICAgIEFXUy5jb25maWcuY3JlZGVudGlhbHMgPSBuZXcgQVdTLkNvZ25pdG9JZGVudGl0eUNyZWRlbnRpYWxzKGNyZWRzKTtcblxuICAgIEFXUy5jb25maWcuY3JlZGVudGlhbHMuZ2V0KGZ1bmN0aW9uIChlcnIpIHtcbiAgICAgICAgaWYgKGVycikge1xuICAgICAgICAgICAgX3RoaXMuc2Vzc2lvblN0YXRlID0gVXNlck1hbmFnZW1lbnQuU2Vzc2lvblN0YXRlLkludmFsaWQ7XG4gICAgICAgICAgICBhcmdzICYmIGFyZ3MuZmFpbHVyZSAmJiBhcmdzLmZhaWx1cmUoZXJyLm1lc3NhZ2UpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIF90aGlzLnNlc3Npb25TdGF0ZSA9IFVzZXJNYW5hZ2VtZW50LlNlc3Npb25TdGF0ZS5WYWxpZDtcbiAgICAgICAgX3RoaXMuZXZlbnRzLmVtaXQoJ3VzZXJNYW5hZ2VtZW50Q3JlZGVudGlhbHNSZWNlaXZlZCcpOyBcbiAgICAgICAgTm9vZGwuUHViU3ViLnJlY29ubmVjdCgpOyAgICAgICBcbiAgICAgICAgYXJncyAmJiBhcmdzLnN1Y2Nlc3MgJiYgYXJncy5zdWNjZXNzKCk7XG4gICAgfSk7ICAgIFxufVxuXG5Vc2VyTWFuYWdlbWVudC5wcm90b3R5cGUuYXR0ZW1wdFNpZ25JbldpdGhDYWNoZWRUb2tlbnMgPSBmdW5jdGlvbiAoYXJncykge1xuICAgIHZhciBfdGhpcyA9IHRoaXM7XG5cbiAgICB2YXIgc2V0dGluZ3MgPSBOb29kbC5nZXRQcm9qZWN0U2V0dGluZ3MoKTtcbiAgICB2YXIgcG9vbERhdGEgPSB7XG4gICAgICAgIFVzZXJQb29sSWQ6IHNldHRpbmdzLnVzZXJNYW5hZ2VtZW50QVdTVXNlclBvb2xJZCwgLy8geW91ciB1c2VyIHBvb2wgaWQgaGVyZVxuICAgICAgICBDbGllbnRJZDogc2V0dGluZ3MudXNlck1hbmFnZW1lbnRBV1NVc2VyUG9vbENsaWVudEFwcElkIC8vIHlvdXIgYXBwIGNsaWVudCBpZCBoZXJlXG4gICAgfTtcbiAgICB2YXIgdXNlclBvb2wgPSBuZXcgQW1hem9uQ29nbml0b0lkZW50aXR5LkNvZ25pdG9Vc2VyUG9vbChwb29sRGF0YSk7XG4gICAgdmFyIGNvZ25pdG9Vc2VyID0gdXNlclBvb2wuZ2V0Q3VycmVudFVzZXIoKTtcblxuICAgIGlmIChjb2duaXRvVXNlciAhPSBudWxsKSB7XG4gICAgICAgIGNvZ25pdG9Vc2VyLmdldFNlc3Npb24oZnVuY3Rpb24gKGVyciwgc2Vzc2lvbikge1xuICAgICAgICAgICAgaWYgKGVycikge1xuICAgICAgICAgICAgICAgIGFyZ3MmJmFyZ3MuZmFpbHVyZSYmYXJncy5mYWlsdXJlKGVyci5tZXNzYWdlKTtcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmKCFzZXNzaW9uLmlzVmFsaWQoKSkge1xuICAgICAgICAgICAgICAgIGFyZ3MmJmFyZ3MuZmFpbHVyZSYmYXJncy5mYWlsdXJlKFwiU2Vzc2lvbiBpcyBub3QgdmFsaWQuXCIpO1xuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgX3RoaXMuZ2V0Q3JlZGVudGlhbHMoc2Vzc2lvbi5nZXRJZFRva2VuKCkuZ2V0Snd0VG9rZW4oKSxhcmdzKTtcbiAgICAgICAgfSk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICB0aGlzLnNlc3Npb25TdGF0ZSA9IFVzZXJNYW5hZ2VtZW50LlNlc3Npb25TdGF0ZS5JbnZhbGlkOyAgICAgICAgXG4gICAgICAgIC8vIE5vdGlmeSBhc3luYywgYWZ0ZXIgYXBwIGhhdmUgYmVlbiBsb2FkZWRcbiAgICAgICAgc2V0VGltZW91dChmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIGFyZ3MmJmFyZ3MuZmFpbHVyZSYmYXJncy5mYWlsdXJlKFwiTm8gdXNlciBjYWNoZWQuXCIpO1xuICAgICAgICB9LDEpO1xuICAgIH1cbn1cblxuVXNlck1hbmFnZW1lbnQucHJvdG90eXBlLnZlcmlmeVVzZXIgPSBmdW5jdGlvbiAodXNlcm5hbWUsIHZlcmlmaWNhdGlvbkNvZGUsIGFyZ3MpIHtcbiAgICB2YXIgX3RoaXMgPSB0aGlzO1xuXG4gICAgdmFyIHNldHRpbmdzID0gTm9vZGwuZ2V0UHJvamVjdFNldHRpbmdzKCk7XG4gICAgdmFyIHBvb2xEYXRhID0ge1xuICAgICAgICBVc2VyUG9vbElkOiBzZXR0aW5ncy51c2VyTWFuYWdlbWVudEFXU1VzZXJQb29sSWQsIC8vIHlvdXIgdXNlciBwb29sIGlkIGhlcmVcbiAgICAgICAgQ2xpZW50SWQ6IHNldHRpbmdzLnVzZXJNYW5hZ2VtZW50QVdTVXNlclBvb2xDbGllbnRBcHBJZCAvLyB5b3VyIGFwcCBjbGllbnQgaWQgaGVyZVxuICAgIH07XG4gICAgdmFyIHVzZXJQb29sID0gbmV3IEFtYXpvbkNvZ25pdG9JZGVudGl0eS5Db2duaXRvVXNlclBvb2wocG9vbERhdGEpO1xuICAgIHZhciB1c2VyRGF0YSA9IHtcbiAgICAgICAgVXNlcm5hbWU6IHVzZXJuYW1lLCAvLyB5b3VyIHVzZXJuYW1lIGhlcmVcbiAgICAgICAgUG9vbDogdXNlclBvb2xcbiAgICB9O1xuICAgIHZhciBjb2duaXRvVXNlciA9IG5ldyBBbWF6b25Db2duaXRvSWRlbnRpdHkuQ29nbml0b1VzZXIodXNlckRhdGEpO1xuXG4gICAgY29nbml0b1VzZXIuY29uZmlybVJlZ2lzdHJhdGlvbih2ZXJpZmljYXRpb25Db2RlLCBmYWxzZSwgZnVuY3Rpb24gKGVyciwgcmVzdWx0KSB7XG4gICAgICAgIGlmIChlcnIpIHtcbiAgICAgICAgICAgIGFyZ3MgJiYgYXJncy5mYWlsdXJlICYmIGFyZ3MuZmFpbHVyZShlcnIubWVzc2FnZSk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cbiAgICAgICAgYXJncyAmJiBhcmdzLnN1Y2Nlc3MgJiYgYXJncy5zdWNjZXNzKCk7XG5cbiAgICAgICAgX3RoaXMuYXR0ZW1wdFNpZ25JbldpdGhDYWNoZWRUb2tlbnMoe1xuICAgICAgICAgICAgZmFpbHVyZTpmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICBfdGhpcy5ldmVudHMuZW1pdCgndXNlck1hbmFnZW1lbnRDYWNoZWRDcmVkZW50aWFsc05vdEF2YWlsYWJsZScpO1xuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHN1Y2Nlc3M6ZnVuY3Rpb24oKSB7IFxuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcblxuICAgIH0pO1xufVxuXG5Vc2VyTWFuYWdlbWVudC5wcm90b3R5cGUucmVzZW5kVmVyaWZpY2F0aW9uQ29kZSA9IGZ1bmN0aW9uICh1c2VybmFtZSwgYXJncykge1xuICAgIHZhciBzZXR0aW5ncyA9IE5vb2RsLmdldFByb2plY3RTZXR0aW5ncygpO1xuICAgIHZhciBwb29sRGF0YSA9IHtcbiAgICAgICAgVXNlclBvb2xJZDogc2V0dGluZ3MudXNlck1hbmFnZW1lbnRBV1NVc2VyUG9vbElkLCAvLyB5b3VyIHVzZXIgcG9vbCBpZCBoZXJlXG4gICAgICAgIENsaWVudElkOiBzZXR0aW5ncy51c2VyTWFuYWdlbWVudEFXU1VzZXJQb29sQ2xpZW50QXBwSWQgLy8geW91ciBhcHAgY2xpZW50IGlkIGhlcmVcbiAgICB9O1xuICAgIHZhciB1c2VyUG9vbCA9IG5ldyBBbWF6b25Db2duaXRvSWRlbnRpdHkuQ29nbml0b1VzZXJQb29sKHBvb2xEYXRhKTtcbiAgICB2YXIgdXNlckRhdGEgPSB7XG4gICAgICAgIFVzZXJuYW1lOiB1c2VybmFtZSwgLy8geW91ciB1c2VybmFtZSBoZXJlXG4gICAgICAgIFBvb2w6IHVzZXJQb29sXG4gICAgfTtcbiAgICB2YXIgY29nbml0b1VzZXIgPSBuZXcgQW1hem9uQ29nbml0b0lkZW50aXR5LkNvZ25pdG9Vc2VyKHVzZXJEYXRhKTtcblxuICAgIGNvZ25pdG9Vc2VyLnJlc2VuZENvbmZpcm1hdGlvbkNvZGUoZnVuY3Rpb24gKGVyciwgcmVzdWx0KSB7XG4gICAgICAgIGlmIChlcnIpIHtcbiAgICAgICAgICAgIGFyZ3MgJiYgYXJncy5mYWlsdXJlICYmIGFyZ3MuZmFpbHVyZShlcnIubWVzc2FnZSk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cbiAgICAgICAgYXJncyAmJiBhcmdzLnN1Y2Nlc3MgJiYgYXJncy5zdWNjZXNzKCk7XG4gICAgfSk7XG59XG5cblVzZXJNYW5hZ2VtZW50LnByb3RvdHlwZS5zaWduVXAgPSBmdW5jdGlvbiAodXNlcm5hbWUsIHBhc3N3b3JkLCBhdHRyaWJ1dGVzLCBhcmdzKSB7XG4gICAgdmFyIHNldHRpbmdzID0gTm9vZGwuZ2V0UHJvamVjdFNldHRpbmdzKCk7XG4gICAgdmFyIHBvb2xEYXRhID0ge1xuICAgICAgICBVc2VyUG9vbElkOiBzZXR0aW5ncy51c2VyTWFuYWdlbWVudEFXU1VzZXJQb29sSWQsIC8vIHlvdXIgdXNlciBwb29sIGlkIGhlcmVcbiAgICAgICAgQ2xpZW50SWQ6IHNldHRpbmdzLnVzZXJNYW5hZ2VtZW50QVdTVXNlclBvb2xDbGllbnRBcHBJZCAvLyB5b3VyIGFwcCBjbGllbnQgaWQgaGVyZVxuICAgIH07XG4gICAgdmFyIHVzZXJQb29sID0gbmV3IEFtYXpvbkNvZ25pdG9JZGVudGl0eS5Db2duaXRvVXNlclBvb2wocG9vbERhdGEpO1xuXG4gICAgdmFyIGF0dHJpYnV0ZUxpc3QgPSBbXTtcblxuICAgIGZvciAodmFyIGkgaW4gYXR0cmlidXRlcykge1xuICAgICAgICB2YXIgYSA9IG5ldyBBbWF6b25Db2duaXRvSWRlbnRpdHkuQ29nbml0b1VzZXJBdHRyaWJ1dGUoeyBOYW1lOiBpLCBWYWx1ZTogYXR0cmlidXRlc1tpXSB9KTtcbiAgICAgICAgYXR0cmlidXRlTGlzdC5wdXNoKGEpO1xuICAgIH1cblxuICAgIHZhciBjb2duaXRvVXNlcjtcbiAgICB1c2VyUG9vbC5zaWduVXAodXNlcm5hbWUsIHBhc3N3b3JkLCBhdHRyaWJ1dGVMaXN0LCBudWxsLCBmdW5jdGlvbiAoZXJyLCByZXN1bHQpIHtcbiAgICAgICAgaWYgKGVycikge1xuICAgICAgICAgICAgYXJncyAmJiBhcmdzLmZhaWx1cmUgJiYgYXJncy5mYWlsdXJlKGVyci5tZXNzYWdlKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIGFyZ3MgJiYgYXJncy5zdWNjZXNzICYmIGFyZ3Muc3VjY2VzcygpO1xuICAgIH0pO1xufVxuXG5Vc2VyTWFuYWdlbWVudC5wcm90b3R5cGUuc2lnbkluID0gZnVuY3Rpb24gKHVzZXJuYW1lLCBwYXNzd29yZCwgYXJncykge1xuICAgIHZhciBfdGhpcyA9IHRoaXM7XG5cbiAgICB2YXIgc2V0dGluZ3MgPSBOb29kbC5nZXRQcm9qZWN0U2V0dGluZ3MoKTtcbiAgICB2YXIgcG9vbERhdGEgPSB7XG4gICAgICAgIFVzZXJQb29sSWQ6IHNldHRpbmdzLnVzZXJNYW5hZ2VtZW50QVdTVXNlclBvb2xJZCwgLy8geW91ciB1c2VyIHBvb2wgaWQgaGVyZVxuICAgICAgICBDbGllbnRJZDogc2V0dGluZ3MudXNlck1hbmFnZW1lbnRBV1NVc2VyUG9vbENsaWVudEFwcElkIC8vIHlvdXIgYXBwIGNsaWVudCBpZCBoZXJlXG4gICAgfTtcbiAgICB2YXIgdXNlclBvb2wgPSBuZXcgQW1hem9uQ29nbml0b0lkZW50aXR5LkNvZ25pdG9Vc2VyUG9vbChwb29sRGF0YSk7XG4gICAgdmFyIHVzZXJEYXRhID0ge1xuICAgICAgICBVc2VybmFtZTogdXNlcm5hbWUsIC8vIHlvdXIgdXNlcm5hbWUgaGVyZVxuICAgICAgICBQb29sOiB1c2VyUG9vbCxcbiAgICAgICAgUGFyYW5vaWEgOiA3ICAgICAgICBcbiAgICB9O1xuXG4gICAgdmFyIGF1dGhlbnRpY2F0aW9uRGF0YSA9IHtcbiAgICAgICAgVXNlcm5hbWU6IHVzZXJuYW1lLCAvLyB5b3VyIHVzZXJuYW1lIGhlcmVcbiAgICAgICAgUGFzc3dvcmQ6IHBhc3N3b3JkLCAvLyB5b3VyIHBhc3N3b3JkIGhlcmVcbiAgICB9O1xuICAgIHZhciBhdXRoZW50aWNhdGlvbkRldGFpbHMgPSBuZXcgQW1hem9uQ29nbml0b0lkZW50aXR5LkF1dGhlbnRpY2F0aW9uRGV0YWlscyhhdXRoZW50aWNhdGlvbkRhdGEpO1xuXG4gICAgdmFyIGNvZ25pdG9Vc2VyID0gbmV3IEFtYXpvbkNvZ25pdG9JZGVudGl0eS5Db2duaXRvVXNlcih1c2VyRGF0YSk7XG4gICAgdGhpcy5zZXNzaW9uU3RhdGUgPSBVc2VyTWFuYWdlbWVudC5TZXNzaW9uU3RhdGUuUGVuZGluZzsgICAgXG4gICAgXG4gICAgY29nbml0b1VzZXIuYXV0aGVudGljYXRlVXNlcihhdXRoZW50aWNhdGlvbkRldGFpbHMsIHtcbiAgICAgICAgb25TdWNjZXNzOiBmdW5jdGlvbiAocmVzdWx0KSB7XG4gICAgICAgICAgICBfdGhpcy5hY2Nlc3NUb2tlbiA9IHJlc3VsdC5nZXRBY2Nlc3NUb2tlbigpO1xuXG4gICAgICAgICAgICBfdGhpcy5nZXRDcmVkZW50aWFscyhyZXN1bHQuZ2V0SWRUb2tlbigpLmdldEp3dFRva2VuKCksYXJncyk7XG4gICAgICAgIH0sXG4gICAgICAgIG9uRmFpbHVyZTogZnVuY3Rpb24gKGVycikge1xuICAgICAgICAgICAgX3RoaXMuc2Vzc2lvblN0YXRlID0gVXNlck1hbmFnZW1lbnQuU2Vzc2lvblN0YXRlLkludmFsaWQ7XG4gICAgICAgICAgICBpZiAoZXJyLmNvZGUgPT09IFwiVXNlck5vdENvbmZpcm1lZEV4Y2VwdGlvblwiKSB7XG4gICAgICAgICAgICAgICAgYXJncyAmJiBhcmdzLnVzZXJOb3RDb25maXJtZWQgJiYgYXJncy51c2VyTm90Q29uZmlybWVkKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICBhcmdzICYmIGFyZ3MuZmFpbHVyZSAmJiBhcmdzLmZhaWx1cmUoZXJyLm1lc3NhZ2UpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgLy8gICBhbGVydChlcnIpO1xuICAgICAgICB9LFxuICAgICAgICBuZXdQYXNzd29yZFJlcXVpcmVkOiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBfdGhpcy5zZXNzaW9uU3RhdGUgPSBVc2VyTWFuYWdlbWVudC5TZXNzaW9uU3RhdGUuSW52YWxpZDtcbiAgICAgICAgICAgIGFyZ3MgJiYgYXJncy5uZXdQYXNzd29yZFJlcXVpcmVkICYmIGFyZ3MubmV3UGFzc3dvcmRSZXF1aXJlZCgpO1xuICAgICAgICB9LFxuLyogICAgICAgIG1mYVJlcXVpcmVkOiBmdW5jdGlvbiAoY29kZURlbGl2ZXJ5RGV0YWlscykge1xuICAgICAgICAgICAgYXJncyAmJiBhcmdzLm1mYVJlcXVpcmVkICYmIGFyZ3MubWZhUmVxdWlyZWQoKTtcbiAgICAgICAgICAgIC8vICAgICB2YXIgdmVyaWZpY2F0aW9uQ29kZSA9IHByb21wdCgnUGxlYXNlIGlucHV0IHZlcmlmaWNhdGlvbiBjb2RlJyAsJycpO1xuICAgICAgICAgICAgLy8gICBjb2duaXRvVXNlci5zZW5kTUZBQ29kZSh2ZXJpZmljYXRpb25Db2RlLCB0aGlzKTtcbiAgICAgICAgfSovXG4gICAgfSk7ICAgIFxufVxuXG5Vc2VyTWFuYWdlbWVudC5wcm90b3R5cGUuc2lnbk91dCA9IGZ1bmN0aW9uKCkge1xuICAgIHZhciBfdGhpcyA9IHRoaXM7XG5cbiAgICB2YXIgc2V0dGluZ3MgPSBOb29kbC5nZXRQcm9qZWN0U2V0dGluZ3MoKTtcbiAgICB2YXIgcG9vbERhdGEgPSB7XG4gICAgICAgIFVzZXJQb29sSWQ6IHNldHRpbmdzLnVzZXJNYW5hZ2VtZW50QVdTVXNlclBvb2xJZCwgLy8geW91ciB1c2VyIHBvb2wgaWQgaGVyZVxuICAgICAgICBDbGllbnRJZDogc2V0dGluZ3MudXNlck1hbmFnZW1lbnRBV1NVc2VyUG9vbENsaWVudEFwcElkIC8vIHlvdXIgYXBwIGNsaWVudCBpZCBoZXJlXG4gICAgfTtcbiAgICB2YXIgdXNlclBvb2wgPSBuZXcgQW1hem9uQ29nbml0b0lkZW50aXR5LkNvZ25pdG9Vc2VyUG9vbChwb29sRGF0YSk7XG4gICAgdmFyIGNvZ25pdG9Vc2VyID0gdXNlclBvb2wuZ2V0Q3VycmVudFVzZXIoKTtcblxuICAgIGlmIChjb2duaXRvVXNlciAhPSBudWxsKSB7XG4gICAgICAgIGNvZ25pdG9Vc2VyLnNpZ25PdXQoKTtcbiAgICAgICAgQVdTLmNvbmZpZy5jcmVkZW50aWFscyYmQVdTLmNvbmZpZy5jcmVkZW50aWFscy5jbGVhckNhY2hlZElkKCk7XG4gICAgfSBcblxuICAgIHRoaXMuc2Vzc2lvblN0YXRlID0gVXNlck1hbmFnZW1lbnQuU2Vzc2lvblN0YXRlLkludmFsaWQ7XG4gICAgX3RoaXMuZXZlbnRzLmVtaXQoJ3VzZXJNYW5hZ2VtZW50U2lnbmVkT3V0Jyk7ICAgICAgIFxufVxuXG5Vc2VyTWFuYWdlbWVudC5wcm90b3R5cGUuZ2V0VXNlcklkID0gZnVuY3Rpb24oKSB7XG4gICAgaWYodGhpcy5zZXNzaW9uU3RhdGUgIT09IFVzZXJNYW5hZ2VtZW50LlNlc3Npb25TdGF0ZS5WYWxpZCkgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICBlbHNlIHJldHVybiBBV1MuY29uZmlnLmNyZWRlbnRpYWxzLmlkZW50aXR5SWQ7XG59XG5cblVzZXJNYW5hZ2VtZW50Lmluc3RhbmNlID0gbmV3IFVzZXJNYW5hZ2VtZW50KCk7XG5cbm1vZHVsZS5leHBvcnRzID0gVXNlck1hbmFnZW1lbnQ7IiwiLy8gQ29weXJpZ2h0IEpveWVudCwgSW5jLiBhbmQgb3RoZXIgTm9kZSBjb250cmlidXRvcnMuXG4vL1xuLy8gUGVybWlzc2lvbiBpcyBoZXJlYnkgZ3JhbnRlZCwgZnJlZSBvZiBjaGFyZ2UsIHRvIGFueSBwZXJzb24gb2J0YWluaW5nIGFcbi8vIGNvcHkgb2YgdGhpcyBzb2Z0d2FyZSBhbmQgYXNzb2NpYXRlZCBkb2N1bWVudGF0aW9uIGZpbGVzICh0aGVcbi8vIFwiU29mdHdhcmVcIiksIHRvIGRlYWwgaW4gdGhlIFNvZnR3YXJlIHdpdGhvdXQgcmVzdHJpY3Rpb24sIGluY2x1ZGluZ1xuLy8gd2l0aG91dCBsaW1pdGF0aW9uIHRoZSByaWdodHMgdG8gdXNlLCBjb3B5LCBtb2RpZnksIG1lcmdlLCBwdWJsaXNoLFxuLy8gZGlzdHJpYnV0ZSwgc3VibGljZW5zZSwgYW5kL29yIHNlbGwgY29waWVzIG9mIHRoZSBTb2Z0d2FyZSwgYW5kIHRvIHBlcm1pdFxuLy8gcGVyc29ucyB0byB3aG9tIHRoZSBTb2Z0d2FyZSBpcyBmdXJuaXNoZWQgdG8gZG8gc28sIHN1YmplY3QgdG8gdGhlXG4vLyBmb2xsb3dpbmcgY29uZGl0aW9uczpcbi8vXG4vLyBUaGUgYWJvdmUgY29weXJpZ2h0IG5vdGljZSBhbmQgdGhpcyBwZXJtaXNzaW9uIG5vdGljZSBzaGFsbCBiZSBpbmNsdWRlZFxuLy8gaW4gYWxsIGNvcGllcyBvciBzdWJzdGFudGlhbCBwb3J0aW9ucyBvZiB0aGUgU29mdHdhcmUuXG4vL1xuLy8gVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiwgV0lUSE9VVCBXQVJSQU5UWSBPRiBBTlkgS0lORCwgRVhQUkVTU1xuLy8gT1IgSU1QTElFRCwgSU5DTFVESU5HIEJVVCBOT1QgTElNSVRFRCBUTyBUSEUgV0FSUkFOVElFUyBPRlxuLy8gTUVSQ0hBTlRBQklMSVRZLCBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRSBBTkQgTk9OSU5GUklOR0VNRU5ULiBJTlxuLy8gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUlMgT1IgQ09QWVJJR0hUIEhPTERFUlMgQkUgTElBQkxFIEZPUiBBTlkgQ0xBSU0sXG4vLyBEQU1BR0VTIE9SIE9USEVSIExJQUJJTElUWSwgV0hFVEhFUiBJTiBBTiBBQ1RJT04gT0YgQ09OVFJBQ1QsIFRPUlQgT1Jcbi8vIE9USEVSV0lTRSwgQVJJU0lORyBGUk9NLCBPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBTT0ZUV0FSRSBPUiBUSEVcbi8vIFVTRSBPUiBPVEhFUiBERUFMSU5HUyBJTiBUSEUgU09GVFdBUkUuXG5cbmZ1bmN0aW9uIEV2ZW50RW1pdHRlcigpIHtcbiAgdGhpcy5fZXZlbnRzID0gdGhpcy5fZXZlbnRzIHx8IHt9O1xuICB0aGlzLl9tYXhMaXN0ZW5lcnMgPSB0aGlzLl9tYXhMaXN0ZW5lcnMgfHwgdW5kZWZpbmVkO1xufVxubW9kdWxlLmV4cG9ydHMgPSBFdmVudEVtaXR0ZXI7XG5cbi8vIEJhY2t3YXJkcy1jb21wYXQgd2l0aCBub2RlIDAuMTAueFxuRXZlbnRFbWl0dGVyLkV2ZW50RW1pdHRlciA9IEV2ZW50RW1pdHRlcjtcblxuRXZlbnRFbWl0dGVyLnByb3RvdHlwZS5fZXZlbnRzID0gdW5kZWZpbmVkO1xuRXZlbnRFbWl0dGVyLnByb3RvdHlwZS5fbWF4TGlzdGVuZXJzID0gdW5kZWZpbmVkO1xuXG4vLyBCeSBkZWZhdWx0IEV2ZW50RW1pdHRlcnMgd2lsbCBwcmludCBhIHdhcm5pbmcgaWYgbW9yZSB0aGFuIDEwIGxpc3RlbmVycyBhcmVcbi8vIGFkZGVkIHRvIGl0LiBUaGlzIGlzIGEgdXNlZnVsIGRlZmF1bHQgd2hpY2ggaGVscHMgZmluZGluZyBtZW1vcnkgbGVha3MuXG5FdmVudEVtaXR0ZXIuZGVmYXVsdE1heExpc3RlbmVycyA9IDEwO1xuXG4vLyBPYnZpb3VzbHkgbm90IGFsbCBFbWl0dGVycyBzaG91bGQgYmUgbGltaXRlZCB0byAxMC4gVGhpcyBmdW5jdGlvbiBhbGxvd3Ncbi8vIHRoYXQgdG8gYmUgaW5jcmVhc2VkLiBTZXQgdG8gemVybyBmb3IgdW5saW1pdGVkLlxuRXZlbnRFbWl0dGVyLnByb3RvdHlwZS5zZXRNYXhMaXN0ZW5lcnMgPSBmdW5jdGlvbihuKSB7XG4gIGlmICghaXNOdW1iZXIobikgfHwgbiA8IDAgfHwgaXNOYU4obikpXG4gICAgdGhyb3cgVHlwZUVycm9yKCduIG11c3QgYmUgYSBwb3NpdGl2ZSBudW1iZXInKTtcbiAgdGhpcy5fbWF4TGlzdGVuZXJzID0gbjtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5FdmVudEVtaXR0ZXIucHJvdG90eXBlLmVtaXQgPSBmdW5jdGlvbih0eXBlKSB7XG4gIHZhciBlciwgaGFuZGxlciwgbGVuLCBhcmdzLCBpLCBsaXN0ZW5lcnM7XG5cbiAgaWYgKCF0aGlzLl9ldmVudHMpXG4gICAgdGhpcy5fZXZlbnRzID0ge307XG5cbiAgLy8gSWYgdGhlcmUgaXMgbm8gJ2Vycm9yJyBldmVudCBsaXN0ZW5lciB0aGVuIHRocm93LlxuICBpZiAodHlwZSA9PT0gJ2Vycm9yJykge1xuICAgIGlmICghdGhpcy5fZXZlbnRzLmVycm9yIHx8XG4gICAgICAgIChpc09iamVjdCh0aGlzLl9ldmVudHMuZXJyb3IpICYmICF0aGlzLl9ldmVudHMuZXJyb3IubGVuZ3RoKSkge1xuICAgICAgZXIgPSBhcmd1bWVudHNbMV07XG4gICAgICBpZiAoZXIgaW5zdGFuY2VvZiBFcnJvcikge1xuICAgICAgICB0aHJvdyBlcjsgLy8gVW5oYW5kbGVkICdlcnJvcicgZXZlbnRcbiAgICAgIH1cbiAgICAgIHRocm93IFR5cGVFcnJvcignVW5jYXVnaHQsIHVuc3BlY2lmaWVkIFwiZXJyb3JcIiBldmVudC4nKTtcbiAgICB9XG4gIH1cblxuICBoYW5kbGVyID0gdGhpcy5fZXZlbnRzW3R5cGVdO1xuXG4gIGlmIChpc1VuZGVmaW5lZChoYW5kbGVyKSlcbiAgICByZXR1cm4gZmFsc2U7XG5cbiAgaWYgKGlzRnVuY3Rpb24oaGFuZGxlcikpIHtcbiAgICBzd2l0Y2ggKGFyZ3VtZW50cy5sZW5ndGgpIHtcbiAgICAgIC8vIGZhc3QgY2FzZXNcbiAgICAgIGNhc2UgMTpcbiAgICAgICAgaGFuZGxlci5jYWxsKHRoaXMpO1xuICAgICAgICBicmVhaztcbiAgICAgIGNhc2UgMjpcbiAgICAgICAgaGFuZGxlci5jYWxsKHRoaXMsIGFyZ3VtZW50c1sxXSk7XG4gICAgICAgIGJyZWFrO1xuICAgICAgY2FzZSAzOlxuICAgICAgICBoYW5kbGVyLmNhbGwodGhpcywgYXJndW1lbnRzWzFdLCBhcmd1bWVudHNbMl0pO1xuICAgICAgICBicmVhaztcbiAgICAgIC8vIHNsb3dlclxuICAgICAgZGVmYXVsdDpcbiAgICAgICAgYXJncyA9IEFycmF5LnByb3RvdHlwZS5zbGljZS5jYWxsKGFyZ3VtZW50cywgMSk7XG4gICAgICAgIGhhbmRsZXIuYXBwbHkodGhpcywgYXJncyk7XG4gICAgfVxuICB9IGVsc2UgaWYgKGlzT2JqZWN0KGhhbmRsZXIpKSB7XG4gICAgYXJncyA9IEFycmF5LnByb3RvdHlwZS5zbGljZS5jYWxsKGFyZ3VtZW50cywgMSk7XG4gICAgbGlzdGVuZXJzID0gaGFuZGxlci5zbGljZSgpO1xuICAgIGxlbiA9IGxpc3RlbmVycy5sZW5ndGg7XG4gICAgZm9yIChpID0gMDsgaSA8IGxlbjsgaSsrKVxuICAgICAgbGlzdGVuZXJzW2ldLmFwcGx5KHRoaXMsIGFyZ3MpO1xuICB9XG5cbiAgcmV0dXJuIHRydWU7XG59O1xuXG5FdmVudEVtaXR0ZXIucHJvdG90eXBlLmFkZExpc3RlbmVyID0gZnVuY3Rpb24odHlwZSwgbGlzdGVuZXIpIHtcbiAgdmFyIG07XG5cbiAgaWYgKCFpc0Z1bmN0aW9uKGxpc3RlbmVyKSlcbiAgICB0aHJvdyBUeXBlRXJyb3IoJ2xpc3RlbmVyIG11c3QgYmUgYSBmdW5jdGlvbicpO1xuXG4gIGlmICghdGhpcy5fZXZlbnRzKVxuICAgIHRoaXMuX2V2ZW50cyA9IHt9O1xuXG4gIC8vIFRvIGF2b2lkIHJlY3Vyc2lvbiBpbiB0aGUgY2FzZSB0aGF0IHR5cGUgPT09IFwibmV3TGlzdGVuZXJcIiEgQmVmb3JlXG4gIC8vIGFkZGluZyBpdCB0byB0aGUgbGlzdGVuZXJzLCBmaXJzdCBlbWl0IFwibmV3TGlzdGVuZXJcIi5cbiAgaWYgKHRoaXMuX2V2ZW50cy5uZXdMaXN0ZW5lcilcbiAgICB0aGlzLmVtaXQoJ25ld0xpc3RlbmVyJywgdHlwZSxcbiAgICAgICAgICAgICAgaXNGdW5jdGlvbihsaXN0ZW5lci5saXN0ZW5lcikgP1xuICAgICAgICAgICAgICBsaXN0ZW5lci5saXN0ZW5lciA6IGxpc3RlbmVyKTtcblxuICBpZiAoIXRoaXMuX2V2ZW50c1t0eXBlXSlcbiAgICAvLyBPcHRpbWl6ZSB0aGUgY2FzZSBvZiBvbmUgbGlzdGVuZXIuIERvbid0IG5lZWQgdGhlIGV4dHJhIGFycmF5IG9iamVjdC5cbiAgICB0aGlzLl9ldmVudHNbdHlwZV0gPSBsaXN0ZW5lcjtcbiAgZWxzZSBpZiAoaXNPYmplY3QodGhpcy5fZXZlbnRzW3R5cGVdKSlcbiAgICAvLyBJZiB3ZSd2ZSBhbHJlYWR5IGdvdCBhbiBhcnJheSwganVzdCBhcHBlbmQuXG4gICAgdGhpcy5fZXZlbnRzW3R5cGVdLnB1c2gobGlzdGVuZXIpO1xuICBlbHNlXG4gICAgLy8gQWRkaW5nIHRoZSBzZWNvbmQgZWxlbWVudCwgbmVlZCB0byBjaGFuZ2UgdG8gYXJyYXkuXG4gICAgdGhpcy5fZXZlbnRzW3R5cGVdID0gW3RoaXMuX2V2ZW50c1t0eXBlXSwgbGlzdGVuZXJdO1xuXG4gIC8vIENoZWNrIGZvciBsaXN0ZW5lciBsZWFrXG4gIGlmIChpc09iamVjdCh0aGlzLl9ldmVudHNbdHlwZV0pICYmICF0aGlzLl9ldmVudHNbdHlwZV0ud2FybmVkKSB7XG4gICAgaWYgKCFpc1VuZGVmaW5lZCh0aGlzLl9tYXhMaXN0ZW5lcnMpKSB7XG4gICAgICBtID0gdGhpcy5fbWF4TGlzdGVuZXJzO1xuICAgIH0gZWxzZSB7XG4gICAgICBtID0gRXZlbnRFbWl0dGVyLmRlZmF1bHRNYXhMaXN0ZW5lcnM7XG4gICAgfVxuXG4gICAgaWYgKG0gJiYgbSA+IDAgJiYgdGhpcy5fZXZlbnRzW3R5cGVdLmxlbmd0aCA+IG0pIHtcbiAgICAgIHRoaXMuX2V2ZW50c1t0eXBlXS53YXJuZWQgPSB0cnVlO1xuICAgICAgY29uc29sZS5lcnJvcignKG5vZGUpIHdhcm5pbmc6IHBvc3NpYmxlIEV2ZW50RW1pdHRlciBtZW1vcnkgJyArXG4gICAgICAgICAgICAgICAgICAgICdsZWFrIGRldGVjdGVkLiAlZCBsaXN0ZW5lcnMgYWRkZWQuICcgK1xuICAgICAgICAgICAgICAgICAgICAnVXNlIGVtaXR0ZXIuc2V0TWF4TGlzdGVuZXJzKCkgdG8gaW5jcmVhc2UgbGltaXQuJyxcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5fZXZlbnRzW3R5cGVdLmxlbmd0aCk7XG4gICAgICBpZiAodHlwZW9mIGNvbnNvbGUudHJhY2UgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgLy8gbm90IHN1cHBvcnRlZCBpbiBJRSAxMFxuICAgICAgICBjb25zb2xlLnRyYWNlKCk7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5FdmVudEVtaXR0ZXIucHJvdG90eXBlLm9uID0gRXZlbnRFbWl0dGVyLnByb3RvdHlwZS5hZGRMaXN0ZW5lcjtcblxuRXZlbnRFbWl0dGVyLnByb3RvdHlwZS5vbmNlID0gZnVuY3Rpb24odHlwZSwgbGlzdGVuZXIpIHtcbiAgaWYgKCFpc0Z1bmN0aW9uKGxpc3RlbmVyKSlcbiAgICB0aHJvdyBUeXBlRXJyb3IoJ2xpc3RlbmVyIG11c3QgYmUgYSBmdW5jdGlvbicpO1xuXG4gIHZhciBmaXJlZCA9IGZhbHNlO1xuXG4gIGZ1bmN0aW9uIGcoKSB7XG4gICAgdGhpcy5yZW1vdmVMaXN0ZW5lcih0eXBlLCBnKTtcblxuICAgIGlmICghZmlyZWQpIHtcbiAgICAgIGZpcmVkID0gdHJ1ZTtcbiAgICAgIGxpc3RlbmVyLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XG4gICAgfVxuICB9XG5cbiAgZy5saXN0ZW5lciA9IGxpc3RlbmVyO1xuICB0aGlzLm9uKHR5cGUsIGcpO1xuXG4gIHJldHVybiB0aGlzO1xufTtcblxuLy8gZW1pdHMgYSAncmVtb3ZlTGlzdGVuZXInIGV2ZW50IGlmZiB0aGUgbGlzdGVuZXIgd2FzIHJlbW92ZWRcbkV2ZW50RW1pdHRlci5wcm90b3R5cGUucmVtb3ZlTGlzdGVuZXIgPSBmdW5jdGlvbih0eXBlLCBsaXN0ZW5lcikge1xuICB2YXIgbGlzdCwgcG9zaXRpb24sIGxlbmd0aCwgaTtcblxuICBpZiAoIWlzRnVuY3Rpb24obGlzdGVuZXIpKVxuICAgIHRocm93IFR5cGVFcnJvcignbGlzdGVuZXIgbXVzdCBiZSBhIGZ1bmN0aW9uJyk7XG5cbiAgaWYgKCF0aGlzLl9ldmVudHMgfHwgIXRoaXMuX2V2ZW50c1t0eXBlXSlcbiAgICByZXR1cm4gdGhpcztcblxuICBsaXN0ID0gdGhpcy5fZXZlbnRzW3R5cGVdO1xuICBsZW5ndGggPSBsaXN0Lmxlbmd0aDtcbiAgcG9zaXRpb24gPSAtMTtcblxuICBpZiAobGlzdCA9PT0gbGlzdGVuZXIgfHxcbiAgICAgIChpc0Z1bmN0aW9uKGxpc3QubGlzdGVuZXIpICYmIGxpc3QubGlzdGVuZXIgPT09IGxpc3RlbmVyKSkge1xuICAgIGRlbGV0ZSB0aGlzLl9ldmVudHNbdHlwZV07XG4gICAgaWYgKHRoaXMuX2V2ZW50cy5yZW1vdmVMaXN0ZW5lcilcbiAgICAgIHRoaXMuZW1pdCgncmVtb3ZlTGlzdGVuZXInLCB0eXBlLCBsaXN0ZW5lcik7XG5cbiAgfSBlbHNlIGlmIChpc09iamVjdChsaXN0KSkge1xuICAgIGZvciAoaSA9IGxlbmd0aDsgaS0tID4gMDspIHtcbiAgICAgIGlmIChsaXN0W2ldID09PSBsaXN0ZW5lciB8fFxuICAgICAgICAgIChsaXN0W2ldLmxpc3RlbmVyICYmIGxpc3RbaV0ubGlzdGVuZXIgPT09IGxpc3RlbmVyKSkge1xuICAgICAgICBwb3NpdGlvbiA9IGk7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChwb3NpdGlvbiA8IDApXG4gICAgICByZXR1cm4gdGhpcztcblxuICAgIGlmIChsaXN0Lmxlbmd0aCA9PT0gMSkge1xuICAgICAgbGlzdC5sZW5ndGggPSAwO1xuICAgICAgZGVsZXRlIHRoaXMuX2V2ZW50c1t0eXBlXTtcbiAgICB9IGVsc2Uge1xuICAgICAgbGlzdC5zcGxpY2UocG9zaXRpb24sIDEpO1xuICAgIH1cblxuICAgIGlmICh0aGlzLl9ldmVudHMucmVtb3ZlTGlzdGVuZXIpXG4gICAgICB0aGlzLmVtaXQoJ3JlbW92ZUxpc3RlbmVyJywgdHlwZSwgbGlzdGVuZXIpO1xuICB9XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5FdmVudEVtaXR0ZXIucHJvdG90eXBlLnJlbW92ZUFsbExpc3RlbmVycyA9IGZ1bmN0aW9uKHR5cGUpIHtcbiAgdmFyIGtleSwgbGlzdGVuZXJzO1xuXG4gIGlmICghdGhpcy5fZXZlbnRzKVxuICAgIHJldHVybiB0aGlzO1xuXG4gIC8vIG5vdCBsaXN0ZW5pbmcgZm9yIHJlbW92ZUxpc3RlbmVyLCBubyBuZWVkIHRvIGVtaXRcbiAgaWYgKCF0aGlzLl9ldmVudHMucmVtb3ZlTGlzdGVuZXIpIHtcbiAgICBpZiAoYXJndW1lbnRzLmxlbmd0aCA9PT0gMClcbiAgICAgIHRoaXMuX2V2ZW50cyA9IHt9O1xuICAgIGVsc2UgaWYgKHRoaXMuX2V2ZW50c1t0eXBlXSlcbiAgICAgIGRlbGV0ZSB0aGlzLl9ldmVudHNbdHlwZV07XG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICAvLyBlbWl0IHJlbW92ZUxpc3RlbmVyIGZvciBhbGwgbGlzdGVuZXJzIG9uIGFsbCBldmVudHNcbiAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPT09IDApIHtcbiAgICBmb3IgKGtleSBpbiB0aGlzLl9ldmVudHMpIHtcbiAgICAgIGlmIChrZXkgPT09ICdyZW1vdmVMaXN0ZW5lcicpIGNvbnRpbnVlO1xuICAgICAgdGhpcy5yZW1vdmVBbGxMaXN0ZW5lcnMoa2V5KTtcbiAgICB9XG4gICAgdGhpcy5yZW1vdmVBbGxMaXN0ZW5lcnMoJ3JlbW92ZUxpc3RlbmVyJyk7XG4gICAgdGhpcy5fZXZlbnRzID0ge307XG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBsaXN0ZW5lcnMgPSB0aGlzLl9ldmVudHNbdHlwZV07XG5cbiAgaWYgKGlzRnVuY3Rpb24obGlzdGVuZXJzKSkge1xuICAgIHRoaXMucmVtb3ZlTGlzdGVuZXIodHlwZSwgbGlzdGVuZXJzKTtcbiAgfSBlbHNlIGlmIChsaXN0ZW5lcnMpIHtcbiAgICAvLyBMSUZPIG9yZGVyXG4gICAgd2hpbGUgKGxpc3RlbmVycy5sZW5ndGgpXG4gICAgICB0aGlzLnJlbW92ZUxpc3RlbmVyKHR5cGUsIGxpc3RlbmVyc1tsaXN0ZW5lcnMubGVuZ3RoIC0gMV0pO1xuICB9XG4gIGRlbGV0ZSB0aGlzLl9ldmVudHNbdHlwZV07XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5FdmVudEVtaXR0ZXIucHJvdG90eXBlLmxpc3RlbmVycyA9IGZ1bmN0aW9uKHR5cGUpIHtcbiAgdmFyIHJldDtcbiAgaWYgKCF0aGlzLl9ldmVudHMgfHwgIXRoaXMuX2V2ZW50c1t0eXBlXSlcbiAgICByZXQgPSBbXTtcbiAgZWxzZSBpZiAoaXNGdW5jdGlvbih0aGlzLl9ldmVudHNbdHlwZV0pKVxuICAgIHJldCA9IFt0aGlzLl9ldmVudHNbdHlwZV1dO1xuICBlbHNlXG4gICAgcmV0ID0gdGhpcy5fZXZlbnRzW3R5cGVdLnNsaWNlKCk7XG4gIHJldHVybiByZXQ7XG59O1xuXG5FdmVudEVtaXR0ZXIucHJvdG90eXBlLmxpc3RlbmVyQ291bnQgPSBmdW5jdGlvbih0eXBlKSB7XG4gIGlmICh0aGlzLl9ldmVudHMpIHtcbiAgICB2YXIgZXZsaXN0ZW5lciA9IHRoaXMuX2V2ZW50c1t0eXBlXTtcblxuICAgIGlmIChpc0Z1bmN0aW9uKGV2bGlzdGVuZXIpKVxuICAgICAgcmV0dXJuIDE7XG4gICAgZWxzZSBpZiAoZXZsaXN0ZW5lcilcbiAgICAgIHJldHVybiBldmxpc3RlbmVyLmxlbmd0aDtcbiAgfVxuICByZXR1cm4gMDtcbn07XG5cbkV2ZW50RW1pdHRlci5saXN0ZW5lckNvdW50ID0gZnVuY3Rpb24oZW1pdHRlciwgdHlwZSkge1xuICByZXR1cm4gZW1pdHRlci5saXN0ZW5lckNvdW50KHR5cGUpO1xufTtcblxuZnVuY3Rpb24gaXNGdW5jdGlvbihhcmcpIHtcbiAgcmV0dXJuIHR5cGVvZiBhcmcgPT09ICdmdW5jdGlvbic7XG59XG5cbmZ1bmN0aW9uIGlzTnVtYmVyKGFyZykge1xuICByZXR1cm4gdHlwZW9mIGFyZyA9PT0gJ251bWJlcic7XG59XG5cbmZ1bmN0aW9uIGlzT2JqZWN0KGFyZykge1xuICByZXR1cm4gdHlwZW9mIGFyZyA9PT0gJ29iamVjdCcgJiYgYXJnICE9PSBudWxsO1xufVxuXG5mdW5jdGlvbiBpc1VuZGVmaW5lZChhcmcpIHtcbiAgcmV0dXJuIGFyZyA9PT0gdm9pZCAwO1xufVxuIiwiaWYgKHR5cGVvZiBPYmplY3QuY3JlYXRlID09PSAnZnVuY3Rpb24nKSB7XG4gIC8vIGltcGxlbWVudGF0aW9uIGZyb20gc3RhbmRhcmQgbm9kZS5qcyAndXRpbCcgbW9kdWxlXG4gIG1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gaW5oZXJpdHMoY3Rvciwgc3VwZXJDdG9yKSB7XG4gICAgY3Rvci5zdXBlcl8gPSBzdXBlckN0b3JcbiAgICBjdG9yLnByb3RvdHlwZSA9IE9iamVjdC5jcmVhdGUoc3VwZXJDdG9yLnByb3RvdHlwZSwge1xuICAgICAgY29uc3RydWN0b3I6IHtcbiAgICAgICAgdmFsdWU6IGN0b3IsXG4gICAgICAgIGVudW1lcmFibGU6IGZhbHNlLFxuICAgICAgICB3cml0YWJsZTogdHJ1ZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgICB9XG4gICAgfSk7XG4gIH07XG59IGVsc2Uge1xuICAvLyBvbGQgc2Nob29sIHNoaW0gZm9yIG9sZCBicm93c2Vyc1xuICBtb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uIGluaGVyaXRzKGN0b3IsIHN1cGVyQ3Rvcikge1xuICAgIGN0b3Iuc3VwZXJfID0gc3VwZXJDdG9yXG4gICAgdmFyIFRlbXBDdG9yID0gZnVuY3Rpb24gKCkge31cbiAgICBUZW1wQ3Rvci5wcm90b3R5cGUgPSBzdXBlckN0b3IucHJvdG90eXBlXG4gICAgY3Rvci5wcm90b3R5cGUgPSBuZXcgVGVtcEN0b3IoKVxuICAgIGN0b3IucHJvdG90eXBlLmNvbnN0cnVjdG9yID0gY3RvclxuICB9XG59XG4iLCIvLyBzaGltIGZvciB1c2luZyBwcm9jZXNzIGluIGJyb3dzZXJcblxudmFyIHByb2Nlc3MgPSBtb2R1bGUuZXhwb3J0cyA9IHt9O1xudmFyIHF1ZXVlID0gW107XG52YXIgZHJhaW5pbmcgPSBmYWxzZTtcbnZhciBjdXJyZW50UXVldWU7XG52YXIgcXVldWVJbmRleCA9IC0xO1xuXG5mdW5jdGlvbiBjbGVhblVwTmV4dFRpY2soKSB7XG4gICAgZHJhaW5pbmcgPSBmYWxzZTtcbiAgICBpZiAoY3VycmVudFF1ZXVlLmxlbmd0aCkge1xuICAgICAgICBxdWV1ZSA9IGN1cnJlbnRRdWV1ZS5jb25jYXQocXVldWUpO1xuICAgIH0gZWxzZSB7XG4gICAgICAgIHF1ZXVlSW5kZXggPSAtMTtcbiAgICB9XG4gICAgaWYgKHF1ZXVlLmxlbmd0aCkge1xuICAgICAgICBkcmFpblF1ZXVlKCk7XG4gICAgfVxufVxuXG5mdW5jdGlvbiBkcmFpblF1ZXVlKCkge1xuICAgIGlmIChkcmFpbmluZykge1xuICAgICAgICByZXR1cm47XG4gICAgfVxuICAgIHZhciB0aW1lb3V0ID0gc2V0VGltZW91dChjbGVhblVwTmV4dFRpY2spO1xuICAgIGRyYWluaW5nID0gdHJ1ZTtcblxuICAgIHZhciBsZW4gPSBxdWV1ZS5sZW5ndGg7XG4gICAgd2hpbGUobGVuKSB7XG4gICAgICAgIGN1cnJlbnRRdWV1ZSA9IHF1ZXVlO1xuICAgICAgICBxdWV1ZSA9IFtdO1xuICAgICAgICB3aGlsZSAoKytxdWV1ZUluZGV4IDwgbGVuKSB7XG4gICAgICAgICAgICBpZiAoY3VycmVudFF1ZXVlKSB7XG4gICAgICAgICAgICAgICAgY3VycmVudFF1ZXVlW3F1ZXVlSW5kZXhdLnJ1bigpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIHF1ZXVlSW5kZXggPSAtMTtcbiAgICAgICAgbGVuID0gcXVldWUubGVuZ3RoO1xuICAgIH1cbiAgICBjdXJyZW50UXVldWUgPSBudWxsO1xuICAgIGRyYWluaW5nID0gZmFsc2U7XG4gICAgY2xlYXJUaW1lb3V0KHRpbWVvdXQpO1xufVxuXG5wcm9jZXNzLm5leHRUaWNrID0gZnVuY3Rpb24gKGZ1bikge1xuICAgIHZhciBhcmdzID0gbmV3IEFycmF5KGFyZ3VtZW50cy5sZW5ndGggLSAxKTtcbiAgICBpZiAoYXJndW1lbnRzLmxlbmd0aCA+IDEpIHtcbiAgICAgICAgZm9yICh2YXIgaSA9IDE7IGkgPCBhcmd1bWVudHMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIGFyZ3NbaSAtIDFdID0gYXJndW1lbnRzW2ldO1xuICAgICAgICB9XG4gICAgfVxuICAgIHF1ZXVlLnB1c2gobmV3IEl0ZW0oZnVuLCBhcmdzKSk7XG4gICAgaWYgKHF1ZXVlLmxlbmd0aCA9PT0gMSAmJiAhZHJhaW5pbmcpIHtcbiAgICAgICAgc2V0VGltZW91dChkcmFpblF1ZXVlLCAwKTtcbiAgICB9XG59O1xuXG4vLyB2OCBsaWtlcyBwcmVkaWN0aWJsZSBvYmplY3RzXG5mdW5jdGlvbiBJdGVtKGZ1biwgYXJyYXkpIHtcbiAgICB0aGlzLmZ1biA9IGZ1bjtcbiAgICB0aGlzLmFycmF5ID0gYXJyYXk7XG59XG5JdGVtLnByb3RvdHlwZS5ydW4gPSBmdW5jdGlvbiAoKSB7XG4gICAgdGhpcy5mdW4uYXBwbHkobnVsbCwgdGhpcy5hcnJheSk7XG59O1xucHJvY2Vzcy50aXRsZSA9ICdicm93c2VyJztcbnByb2Nlc3MuYnJvd3NlciA9IHRydWU7XG5wcm9jZXNzLmVudiA9IHt9O1xucHJvY2Vzcy5hcmd2ID0gW107XG5wcm9jZXNzLnZlcnNpb24gPSAnJzsgLy8gZW1wdHkgc3RyaW5nIHRvIGF2b2lkIHJlZ2V4cCBpc3N1ZXNcbnByb2Nlc3MudmVyc2lvbnMgPSB7fTtcblxuZnVuY3Rpb24gbm9vcCgpIHt9XG5cbnByb2Nlc3Mub24gPSBub29wO1xucHJvY2Vzcy5hZGRMaXN0ZW5lciA9IG5vb3A7XG5wcm9jZXNzLm9uY2UgPSBub29wO1xucHJvY2Vzcy5vZmYgPSBub29wO1xucHJvY2Vzcy5yZW1vdmVMaXN0ZW5lciA9IG5vb3A7XG5wcm9jZXNzLnJlbW92ZUFsbExpc3RlbmVycyA9IG5vb3A7XG5wcm9jZXNzLmVtaXQgPSBub29wO1xuXG5wcm9jZXNzLmJpbmRpbmcgPSBmdW5jdGlvbiAobmFtZSkge1xuICAgIHRocm93IG5ldyBFcnJvcigncHJvY2Vzcy5iaW5kaW5nIGlzIG5vdCBzdXBwb3J0ZWQnKTtcbn07XG5cbnByb2Nlc3MuY3dkID0gZnVuY3Rpb24gKCkgeyByZXR1cm4gJy8nIH07XG5wcm9jZXNzLmNoZGlyID0gZnVuY3Rpb24gKGRpcikge1xuICAgIHRocm93IG5ldyBFcnJvcigncHJvY2Vzcy5jaGRpciBpcyBub3Qgc3VwcG9ydGVkJyk7XG59O1xucHJvY2Vzcy51bWFzayA9IGZ1bmN0aW9uKCkgeyByZXR1cm4gMDsgfTtcbiIsIm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gaXNCdWZmZXIoYXJnKSB7XG4gIHJldHVybiBhcmcgJiYgdHlwZW9mIGFyZyA9PT0gJ29iamVjdCdcbiAgICAmJiB0eXBlb2YgYXJnLmNvcHkgPT09ICdmdW5jdGlvbidcbiAgICAmJiB0eXBlb2YgYXJnLmZpbGwgPT09ICdmdW5jdGlvbidcbiAgICAmJiB0eXBlb2YgYXJnLnJlYWRVSW50OCA9PT0gJ2Z1bmN0aW9uJztcbn0iLCIvLyBDb3B5cmlnaHQgSm95ZW50LCBJbmMuIGFuZCBvdGhlciBOb2RlIGNvbnRyaWJ1dG9ycy5cbi8vXG4vLyBQZXJtaXNzaW9uIGlzIGhlcmVieSBncmFudGVkLCBmcmVlIG9mIGNoYXJnZSwgdG8gYW55IHBlcnNvbiBvYnRhaW5pbmcgYVxuLy8gY29weSBvZiB0aGlzIHNvZnR3YXJlIGFuZCBhc3NvY2lhdGVkIGRvY3VtZW50YXRpb24gZmlsZXMgKHRoZVxuLy8gXCJTb2Z0d2FyZVwiKSwgdG8gZGVhbCBpbiB0aGUgU29mdHdhcmUgd2l0aG91dCByZXN0cmljdGlvbiwgaW5jbHVkaW5nXG4vLyB3aXRob3V0IGxpbWl0YXRpb24gdGhlIHJpZ2h0cyB0byB1c2UsIGNvcHksIG1vZGlmeSwgbWVyZ2UsIHB1Ymxpc2gsXG4vLyBkaXN0cmlidXRlLCBzdWJsaWNlbnNlLCBhbmQvb3Igc2VsbCBjb3BpZXMgb2YgdGhlIFNvZnR3YXJlLCBhbmQgdG8gcGVybWl0XG4vLyBwZXJzb25zIHRvIHdob20gdGhlIFNvZnR3YXJlIGlzIGZ1cm5pc2hlZCB0byBkbyBzbywgc3ViamVjdCB0byB0aGVcbi8vIGZvbGxvd2luZyBjb25kaXRpb25zOlxuLy9cbi8vIFRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlIGFuZCB0aGlzIHBlcm1pc3Npb24gbm90aWNlIHNoYWxsIGJlIGluY2x1ZGVkXG4vLyBpbiBhbGwgY29waWVzIG9yIHN1YnN0YW50aWFsIHBvcnRpb25zIG9mIHRoZSBTb2Z0d2FyZS5cbi8vXG4vLyBUSEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiLCBXSVRIT1VUIFdBUlJBTlRZIE9GIEFOWSBLSU5ELCBFWFBSRVNTXG4vLyBPUiBJTVBMSUVELCBJTkNMVURJTkcgQlVUIE5PVCBMSU1JVEVEIFRPIFRIRSBXQVJSQU5USUVTIE9GXG4vLyBNRVJDSEFOVEFCSUxJVFksIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFIEFORCBOT05JTkZSSU5HRU1FTlQuIElOXG4vLyBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SUyBPUiBDT1BZUklHSFQgSE9MREVSUyBCRSBMSUFCTEUgRk9SIEFOWSBDTEFJTSxcbi8vIERBTUFHRVMgT1IgT1RIRVIgTElBQklMSVRZLCBXSEVUSEVSIElOIEFOIEFDVElPTiBPRiBDT05UUkFDVCwgVE9SVCBPUlxuLy8gT1RIRVJXSVNFLCBBUklTSU5HIEZST00sIE9VVCBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFNPRlRXQVJFIE9SIFRIRVxuLy8gVVNFIE9SIE9USEVSIERFQUxJTkdTIElOIFRIRSBTT0ZUV0FSRS5cblxudmFyIGZvcm1hdFJlZ0V4cCA9IC8lW3NkaiVdL2c7XG5leHBvcnRzLmZvcm1hdCA9IGZ1bmN0aW9uKGYpIHtcbiAgaWYgKCFpc1N0cmluZyhmKSkge1xuICAgIHZhciBvYmplY3RzID0gW107XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhcmd1bWVudHMubGVuZ3RoOyBpKyspIHtcbiAgICAgIG9iamVjdHMucHVzaChpbnNwZWN0KGFyZ3VtZW50c1tpXSkpO1xuICAgIH1cbiAgICByZXR1cm4gb2JqZWN0cy5qb2luKCcgJyk7XG4gIH1cblxuICB2YXIgaSA9IDE7XG4gIHZhciBhcmdzID0gYXJndW1lbnRzO1xuICB2YXIgbGVuID0gYXJncy5sZW5ndGg7XG4gIHZhciBzdHIgPSBTdHJpbmcoZikucmVwbGFjZShmb3JtYXRSZWdFeHAsIGZ1bmN0aW9uKHgpIHtcbiAgICBpZiAoeCA9PT0gJyUlJykgcmV0dXJuICclJztcbiAgICBpZiAoaSA+PSBsZW4pIHJldHVybiB4O1xuICAgIHN3aXRjaCAoeCkge1xuICAgICAgY2FzZSAnJXMnOiByZXR1cm4gU3RyaW5nKGFyZ3NbaSsrXSk7XG4gICAgICBjYXNlICclZCc6IHJldHVybiBOdW1iZXIoYXJnc1tpKytdKTtcbiAgICAgIGNhc2UgJyVqJzpcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkoYXJnc1tpKytdKTtcbiAgICAgICAgfSBjYXRjaCAoXykge1xuICAgICAgICAgIHJldHVybiAnW0NpcmN1bGFyXSc7XG4gICAgICAgIH1cbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIHJldHVybiB4O1xuICAgIH1cbiAgfSk7XG4gIGZvciAodmFyIHggPSBhcmdzW2ldOyBpIDwgbGVuOyB4ID0gYXJnc1srK2ldKSB7XG4gICAgaWYgKGlzTnVsbCh4KSB8fCAhaXNPYmplY3QoeCkpIHtcbiAgICAgIHN0ciArPSAnICcgKyB4O1xuICAgIH0gZWxzZSB7XG4gICAgICBzdHIgKz0gJyAnICsgaW5zcGVjdCh4KTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIHN0cjtcbn07XG5cblxuLy8gTWFyayB0aGF0IGEgbWV0aG9kIHNob3VsZCBub3QgYmUgdXNlZC5cbi8vIFJldHVybnMgYSBtb2RpZmllZCBmdW5jdGlvbiB3aGljaCB3YXJucyBvbmNlIGJ5IGRlZmF1bHQuXG4vLyBJZiAtLW5vLWRlcHJlY2F0aW9uIGlzIHNldCwgdGhlbiBpdCBpcyBhIG5vLW9wLlxuZXhwb3J0cy5kZXByZWNhdGUgPSBmdW5jdGlvbihmbiwgbXNnKSB7XG4gIC8vIEFsbG93IGZvciBkZXByZWNhdGluZyB0aGluZ3MgaW4gdGhlIHByb2Nlc3Mgb2Ygc3RhcnRpbmcgdXAuXG4gIGlmIChpc1VuZGVmaW5lZChnbG9iYWwucHJvY2VzcykpIHtcbiAgICByZXR1cm4gZnVuY3Rpb24oKSB7XG4gICAgICByZXR1cm4gZXhwb3J0cy5kZXByZWNhdGUoZm4sIG1zZykuYXBwbHkodGhpcywgYXJndW1lbnRzKTtcbiAgICB9O1xuICB9XG5cbiAgaWYgKHByb2Nlc3Mubm9EZXByZWNhdGlvbiA9PT0gdHJ1ZSkge1xuICAgIHJldHVybiBmbjtcbiAgfVxuXG4gIHZhciB3YXJuZWQgPSBmYWxzZTtcbiAgZnVuY3Rpb24gZGVwcmVjYXRlZCgpIHtcbiAgICBpZiAoIXdhcm5lZCkge1xuICAgICAgaWYgKHByb2Nlc3MudGhyb3dEZXByZWNhdGlvbikge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IobXNnKTtcbiAgICAgIH0gZWxzZSBpZiAocHJvY2Vzcy50cmFjZURlcHJlY2F0aW9uKSB7XG4gICAgICAgIGNvbnNvbGUudHJhY2UobXNnKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IobXNnKTtcbiAgICAgIH1cbiAgICAgIHdhcm5lZCA9IHRydWU7XG4gICAgfVxuICAgIHJldHVybiBmbi5hcHBseSh0aGlzLCBhcmd1bWVudHMpO1xuICB9XG5cbiAgcmV0dXJuIGRlcHJlY2F0ZWQ7XG59O1xuXG5cbnZhciBkZWJ1Z3MgPSB7fTtcbnZhciBkZWJ1Z0Vudmlyb247XG5leHBvcnRzLmRlYnVnbG9nID0gZnVuY3Rpb24oc2V0KSB7XG4gIGlmIChpc1VuZGVmaW5lZChkZWJ1Z0Vudmlyb24pKVxuICAgIGRlYnVnRW52aXJvbiA9IHByb2Nlc3MuZW52Lk5PREVfREVCVUcgfHwgJyc7XG4gIHNldCA9IHNldC50b1VwcGVyQ2FzZSgpO1xuICBpZiAoIWRlYnVnc1tzZXRdKSB7XG4gICAgaWYgKG5ldyBSZWdFeHAoJ1xcXFxiJyArIHNldCArICdcXFxcYicsICdpJykudGVzdChkZWJ1Z0Vudmlyb24pKSB7XG4gICAgICB2YXIgcGlkID0gcHJvY2Vzcy5waWQ7XG4gICAgICBkZWJ1Z3Nbc2V0XSA9IGZ1bmN0aW9uKCkge1xuICAgICAgICB2YXIgbXNnID0gZXhwb3J0cy5mb3JtYXQuYXBwbHkoZXhwb3J0cywgYXJndW1lbnRzKTtcbiAgICAgICAgY29uc29sZS5lcnJvcignJXMgJWQ6ICVzJywgc2V0LCBwaWQsIG1zZyk7XG4gICAgICB9O1xuICAgIH0gZWxzZSB7XG4gICAgICBkZWJ1Z3Nbc2V0XSA9IGZ1bmN0aW9uKCkge307XG4gICAgfVxuICB9XG4gIHJldHVybiBkZWJ1Z3Nbc2V0XTtcbn07XG5cblxuLyoqXG4gKiBFY2hvcyB0aGUgdmFsdWUgb2YgYSB2YWx1ZS4gVHJ5cyB0byBwcmludCB0aGUgdmFsdWUgb3V0XG4gKiBpbiB0aGUgYmVzdCB3YXkgcG9zc2libGUgZ2l2ZW4gdGhlIGRpZmZlcmVudCB0eXBlcy5cbiAqXG4gKiBAcGFyYW0ge09iamVjdH0gb2JqIFRoZSBvYmplY3QgdG8gcHJpbnQgb3V0LlxuICogQHBhcmFtIHtPYmplY3R9IG9wdHMgT3B0aW9uYWwgb3B0aW9ucyBvYmplY3QgdGhhdCBhbHRlcnMgdGhlIG91dHB1dC5cbiAqL1xuLyogbGVnYWN5OiBvYmosIHNob3dIaWRkZW4sIGRlcHRoLCBjb2xvcnMqL1xuZnVuY3Rpb24gaW5zcGVjdChvYmosIG9wdHMpIHtcbiAgLy8gZGVmYXVsdCBvcHRpb25zXG4gIHZhciBjdHggPSB7XG4gICAgc2VlbjogW10sXG4gICAgc3R5bGl6ZTogc3R5bGl6ZU5vQ29sb3JcbiAgfTtcbiAgLy8gbGVnYWN5Li4uXG4gIGlmIChhcmd1bWVudHMubGVuZ3RoID49IDMpIGN0eC5kZXB0aCA9IGFyZ3VtZW50c1syXTtcbiAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPj0gNCkgY3R4LmNvbG9ycyA9IGFyZ3VtZW50c1szXTtcbiAgaWYgKGlzQm9vbGVhbihvcHRzKSkge1xuICAgIC8vIGxlZ2FjeS4uLlxuICAgIGN0eC5zaG93SGlkZGVuID0gb3B0cztcbiAgfSBlbHNlIGlmIChvcHRzKSB7XG4gICAgLy8gZ290IGFuIFwib3B0aW9uc1wiIG9iamVjdFxuICAgIGV4cG9ydHMuX2V4dGVuZChjdHgsIG9wdHMpO1xuICB9XG4gIC8vIHNldCBkZWZhdWx0IG9wdGlvbnNcbiAgaWYgKGlzVW5kZWZpbmVkKGN0eC5zaG93SGlkZGVuKSkgY3R4LnNob3dIaWRkZW4gPSBmYWxzZTtcbiAgaWYgKGlzVW5kZWZpbmVkKGN0eC5kZXB0aCkpIGN0eC5kZXB0aCA9IDI7XG4gIGlmIChpc1VuZGVmaW5lZChjdHguY29sb3JzKSkgY3R4LmNvbG9ycyA9IGZhbHNlO1xuICBpZiAoaXNVbmRlZmluZWQoY3R4LmN1c3RvbUluc3BlY3QpKSBjdHguY3VzdG9tSW5zcGVjdCA9IHRydWU7XG4gIGlmIChjdHguY29sb3JzKSBjdHguc3R5bGl6ZSA9IHN0eWxpemVXaXRoQ29sb3I7XG4gIHJldHVybiBmb3JtYXRWYWx1ZShjdHgsIG9iaiwgY3R4LmRlcHRoKTtcbn1cbmV4cG9ydHMuaW5zcGVjdCA9IGluc3BlY3Q7XG5cblxuLy8gaHR0cDovL2VuLndpa2lwZWRpYS5vcmcvd2lraS9BTlNJX2VzY2FwZV9jb2RlI2dyYXBoaWNzXG5pbnNwZWN0LmNvbG9ycyA9IHtcbiAgJ2JvbGQnIDogWzEsIDIyXSxcbiAgJ2l0YWxpYycgOiBbMywgMjNdLFxuICAndW5kZXJsaW5lJyA6IFs0LCAyNF0sXG4gICdpbnZlcnNlJyA6IFs3LCAyN10sXG4gICd3aGl0ZScgOiBbMzcsIDM5XSxcbiAgJ2dyZXknIDogWzkwLCAzOV0sXG4gICdibGFjaycgOiBbMzAsIDM5XSxcbiAgJ2JsdWUnIDogWzM0LCAzOV0sXG4gICdjeWFuJyA6IFszNiwgMzldLFxuICAnZ3JlZW4nIDogWzMyLCAzOV0sXG4gICdtYWdlbnRhJyA6IFszNSwgMzldLFxuICAncmVkJyA6IFszMSwgMzldLFxuICAneWVsbG93JyA6IFszMywgMzldXG59O1xuXG4vLyBEb24ndCB1c2UgJ2JsdWUnIG5vdCB2aXNpYmxlIG9uIGNtZC5leGVcbmluc3BlY3Quc3R5bGVzID0ge1xuICAnc3BlY2lhbCc6ICdjeWFuJyxcbiAgJ251bWJlcic6ICd5ZWxsb3cnLFxuICAnYm9vbGVhbic6ICd5ZWxsb3cnLFxuICAndW5kZWZpbmVkJzogJ2dyZXknLFxuICAnbnVsbCc6ICdib2xkJyxcbiAgJ3N0cmluZyc6ICdncmVlbicsXG4gICdkYXRlJzogJ21hZ2VudGEnLFxuICAvLyBcIm5hbWVcIjogaW50ZW50aW9uYWxseSBub3Qgc3R5bGluZ1xuICAncmVnZXhwJzogJ3JlZCdcbn07XG5cblxuZnVuY3Rpb24gc3R5bGl6ZVdpdGhDb2xvcihzdHIsIHN0eWxlVHlwZSkge1xuICB2YXIgc3R5bGUgPSBpbnNwZWN0LnN0eWxlc1tzdHlsZVR5cGVdO1xuXG4gIGlmIChzdHlsZSkge1xuICAgIHJldHVybiAnXFx1MDAxYlsnICsgaW5zcGVjdC5jb2xvcnNbc3R5bGVdWzBdICsgJ20nICsgc3RyICtcbiAgICAgICAgICAgJ1xcdTAwMWJbJyArIGluc3BlY3QuY29sb3JzW3N0eWxlXVsxXSArICdtJztcbiAgfSBlbHNlIHtcbiAgICByZXR1cm4gc3RyO1xuICB9XG59XG5cblxuZnVuY3Rpb24gc3R5bGl6ZU5vQ29sb3Ioc3RyLCBzdHlsZVR5cGUpIHtcbiAgcmV0dXJuIHN0cjtcbn1cblxuXG5mdW5jdGlvbiBhcnJheVRvSGFzaChhcnJheSkge1xuICB2YXIgaGFzaCA9IHt9O1xuXG4gIGFycmF5LmZvckVhY2goZnVuY3Rpb24odmFsLCBpZHgpIHtcbiAgICBoYXNoW3ZhbF0gPSB0cnVlO1xuICB9KTtcblxuICByZXR1cm4gaGFzaDtcbn1cblxuXG5mdW5jdGlvbiBmb3JtYXRWYWx1ZShjdHgsIHZhbHVlLCByZWN1cnNlVGltZXMpIHtcbiAgLy8gUHJvdmlkZSBhIGhvb2sgZm9yIHVzZXItc3BlY2lmaWVkIGluc3BlY3QgZnVuY3Rpb25zLlxuICAvLyBDaGVjayB0aGF0IHZhbHVlIGlzIGFuIG9iamVjdCB3aXRoIGFuIGluc3BlY3QgZnVuY3Rpb24gb24gaXRcbiAgaWYgKGN0eC5jdXN0b21JbnNwZWN0ICYmXG4gICAgICB2YWx1ZSAmJlxuICAgICAgaXNGdW5jdGlvbih2YWx1ZS5pbnNwZWN0KSAmJlxuICAgICAgLy8gRmlsdGVyIG91dCB0aGUgdXRpbCBtb2R1bGUsIGl0J3MgaW5zcGVjdCBmdW5jdGlvbiBpcyBzcGVjaWFsXG4gICAgICB2YWx1ZS5pbnNwZWN0ICE9PSBleHBvcnRzLmluc3BlY3QgJiZcbiAgICAgIC8vIEFsc28gZmlsdGVyIG91dCBhbnkgcHJvdG90eXBlIG9iamVjdHMgdXNpbmcgdGhlIGNpcmN1bGFyIGNoZWNrLlxuICAgICAgISh2YWx1ZS5jb25zdHJ1Y3RvciAmJiB2YWx1ZS5jb25zdHJ1Y3Rvci5wcm90b3R5cGUgPT09IHZhbHVlKSkge1xuICAgIHZhciByZXQgPSB2YWx1ZS5pbnNwZWN0KHJlY3Vyc2VUaW1lcywgY3R4KTtcbiAgICBpZiAoIWlzU3RyaW5nKHJldCkpIHtcbiAgICAgIHJldCA9IGZvcm1hdFZhbHVlKGN0eCwgcmV0LCByZWN1cnNlVGltZXMpO1xuICAgIH1cbiAgICByZXR1cm4gcmV0O1xuICB9XG5cbiAgLy8gUHJpbWl0aXZlIHR5cGVzIGNhbm5vdCBoYXZlIHByb3BlcnRpZXNcbiAgdmFyIHByaW1pdGl2ZSA9IGZvcm1hdFByaW1pdGl2ZShjdHgsIHZhbHVlKTtcbiAgaWYgKHByaW1pdGl2ZSkge1xuICAgIHJldHVybiBwcmltaXRpdmU7XG4gIH1cblxuICAvLyBMb29rIHVwIHRoZSBrZXlzIG9mIHRoZSBvYmplY3QuXG4gIHZhciBrZXlzID0gT2JqZWN0LmtleXModmFsdWUpO1xuICB2YXIgdmlzaWJsZUtleXMgPSBhcnJheVRvSGFzaChrZXlzKTtcblxuICBpZiAoY3R4LnNob3dIaWRkZW4pIHtcbiAgICBrZXlzID0gT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModmFsdWUpO1xuICB9XG5cbiAgLy8gSUUgZG9lc24ndCBtYWtlIGVycm9yIGZpZWxkcyBub24tZW51bWVyYWJsZVxuICAvLyBodHRwOi8vbXNkbi5taWNyb3NvZnQuY29tL2VuLXVzL2xpYnJhcnkvaWUvZHd3NTJzYnQodj12cy45NCkuYXNweFxuICBpZiAoaXNFcnJvcih2YWx1ZSlcbiAgICAgICYmIChrZXlzLmluZGV4T2YoJ21lc3NhZ2UnKSA+PSAwIHx8IGtleXMuaW5kZXhPZignZGVzY3JpcHRpb24nKSA+PSAwKSkge1xuICAgIHJldHVybiBmb3JtYXRFcnJvcih2YWx1ZSk7XG4gIH1cblxuICAvLyBTb21lIHR5cGUgb2Ygb2JqZWN0IHdpdGhvdXQgcHJvcGVydGllcyBjYW4gYmUgc2hvcnRjdXR0ZWQuXG4gIGlmIChrZXlzLmxlbmd0aCA9PT0gMCkge1xuICAgIGlmIChpc0Z1bmN0aW9uKHZhbHVlKSkge1xuICAgICAgdmFyIG5hbWUgPSB2YWx1ZS5uYW1lID8gJzogJyArIHZhbHVlLm5hbWUgOiAnJztcbiAgICAgIHJldHVybiBjdHguc3R5bGl6ZSgnW0Z1bmN0aW9uJyArIG5hbWUgKyAnXScsICdzcGVjaWFsJyk7XG4gICAgfVxuICAgIGlmIChpc1JlZ0V4cCh2YWx1ZSkpIHtcbiAgICAgIHJldHVybiBjdHguc3R5bGl6ZShSZWdFeHAucHJvdG90eXBlLnRvU3RyaW5nLmNhbGwodmFsdWUpLCAncmVnZXhwJyk7XG4gICAgfVxuICAgIGlmIChpc0RhdGUodmFsdWUpKSB7XG4gICAgICByZXR1cm4gY3R4LnN0eWxpemUoRGF0ZS5wcm90b3R5cGUudG9TdHJpbmcuY2FsbCh2YWx1ZSksICdkYXRlJyk7XG4gICAgfVxuICAgIGlmIChpc0Vycm9yKHZhbHVlKSkge1xuICAgICAgcmV0dXJuIGZvcm1hdEVycm9yKHZhbHVlKTtcbiAgICB9XG4gIH1cblxuICB2YXIgYmFzZSA9ICcnLCBhcnJheSA9IGZhbHNlLCBicmFjZXMgPSBbJ3snLCAnfSddO1xuXG4gIC8vIE1ha2UgQXJyYXkgc2F5IHRoYXQgdGhleSBhcmUgQXJyYXlcbiAgaWYgKGlzQXJyYXkodmFsdWUpKSB7XG4gICAgYXJyYXkgPSB0cnVlO1xuICAgIGJyYWNlcyA9IFsnWycsICddJ107XG4gIH1cblxuICAvLyBNYWtlIGZ1bmN0aW9ucyBzYXkgdGhhdCB0aGV5IGFyZSBmdW5jdGlvbnNcbiAgaWYgKGlzRnVuY3Rpb24odmFsdWUpKSB7XG4gICAgdmFyIG4gPSB2YWx1ZS5uYW1lID8gJzogJyArIHZhbHVlLm5hbWUgOiAnJztcbiAgICBiYXNlID0gJyBbRnVuY3Rpb24nICsgbiArICddJztcbiAgfVxuXG4gIC8vIE1ha2UgUmVnRXhwcyBzYXkgdGhhdCB0aGV5IGFyZSBSZWdFeHBzXG4gIGlmIChpc1JlZ0V4cCh2YWx1ZSkpIHtcbiAgICBiYXNlID0gJyAnICsgUmVnRXhwLnByb3RvdHlwZS50b1N0cmluZy5jYWxsKHZhbHVlKTtcbiAgfVxuXG4gIC8vIE1ha2UgZGF0ZXMgd2l0aCBwcm9wZXJ0aWVzIGZpcnN0IHNheSB0aGUgZGF0ZVxuICBpZiAoaXNEYXRlKHZhbHVlKSkge1xuICAgIGJhc2UgPSAnICcgKyBEYXRlLnByb3RvdHlwZS50b1VUQ1N0cmluZy5jYWxsKHZhbHVlKTtcbiAgfVxuXG4gIC8vIE1ha2UgZXJyb3Igd2l0aCBtZXNzYWdlIGZpcnN0IHNheSB0aGUgZXJyb3JcbiAgaWYgKGlzRXJyb3IodmFsdWUpKSB7XG4gICAgYmFzZSA9ICcgJyArIGZvcm1hdEVycm9yKHZhbHVlKTtcbiAgfVxuXG4gIGlmIChrZXlzLmxlbmd0aCA9PT0gMCAmJiAoIWFycmF5IHx8IHZhbHVlLmxlbmd0aCA9PSAwKSkge1xuICAgIHJldHVybiBicmFjZXNbMF0gKyBiYXNlICsgYnJhY2VzWzFdO1xuICB9XG5cbiAgaWYgKHJlY3Vyc2VUaW1lcyA8IDApIHtcbiAgICBpZiAoaXNSZWdFeHAodmFsdWUpKSB7XG4gICAgICByZXR1cm4gY3R4LnN0eWxpemUoUmVnRXhwLnByb3RvdHlwZS50b1N0cmluZy5jYWxsKHZhbHVlKSwgJ3JlZ2V4cCcpO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXR1cm4gY3R4LnN0eWxpemUoJ1tPYmplY3RdJywgJ3NwZWNpYWwnKTtcbiAgICB9XG4gIH1cblxuICBjdHguc2Vlbi5wdXNoKHZhbHVlKTtcblxuICB2YXIgb3V0cHV0O1xuICBpZiAoYXJyYXkpIHtcbiAgICBvdXRwdXQgPSBmb3JtYXRBcnJheShjdHgsIHZhbHVlLCByZWN1cnNlVGltZXMsIHZpc2libGVLZXlzLCBrZXlzKTtcbiAgfSBlbHNlIHtcbiAgICBvdXRwdXQgPSBrZXlzLm1hcChmdW5jdGlvbihrZXkpIHtcbiAgICAgIHJldHVybiBmb3JtYXRQcm9wZXJ0eShjdHgsIHZhbHVlLCByZWN1cnNlVGltZXMsIHZpc2libGVLZXlzLCBrZXksIGFycmF5KTtcbiAgICB9KTtcbiAgfVxuXG4gIGN0eC5zZWVuLnBvcCgpO1xuXG4gIHJldHVybiByZWR1Y2VUb1NpbmdsZVN0cmluZyhvdXRwdXQsIGJhc2UsIGJyYWNlcyk7XG59XG5cblxuZnVuY3Rpb24gZm9ybWF0UHJpbWl0aXZlKGN0eCwgdmFsdWUpIHtcbiAgaWYgKGlzVW5kZWZpbmVkKHZhbHVlKSlcbiAgICByZXR1cm4gY3R4LnN0eWxpemUoJ3VuZGVmaW5lZCcsICd1bmRlZmluZWQnKTtcbiAgaWYgKGlzU3RyaW5nKHZhbHVlKSkge1xuICAgIHZhciBzaW1wbGUgPSAnXFwnJyArIEpTT04uc3RyaW5naWZ5KHZhbHVlKS5yZXBsYWNlKC9eXCJ8XCIkL2csICcnKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLnJlcGxhY2UoLycvZywgXCJcXFxcJ1wiKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLnJlcGxhY2UoL1xcXFxcIi9nLCAnXCInKSArICdcXCcnO1xuICAgIHJldHVybiBjdHguc3R5bGl6ZShzaW1wbGUsICdzdHJpbmcnKTtcbiAgfVxuICBpZiAoaXNOdW1iZXIodmFsdWUpKVxuICAgIHJldHVybiBjdHguc3R5bGl6ZSgnJyArIHZhbHVlLCAnbnVtYmVyJyk7XG4gIGlmIChpc0Jvb2xlYW4odmFsdWUpKVxuICAgIHJldHVybiBjdHguc3R5bGl6ZSgnJyArIHZhbHVlLCAnYm9vbGVhbicpO1xuICAvLyBGb3Igc29tZSByZWFzb24gdHlwZW9mIG51bGwgaXMgXCJvYmplY3RcIiwgc28gc3BlY2lhbCBjYXNlIGhlcmUuXG4gIGlmIChpc051bGwodmFsdWUpKVxuICAgIHJldHVybiBjdHguc3R5bGl6ZSgnbnVsbCcsICdudWxsJyk7XG59XG5cblxuZnVuY3Rpb24gZm9ybWF0RXJyb3IodmFsdWUpIHtcbiAgcmV0dXJuICdbJyArIEVycm9yLnByb3RvdHlwZS50b1N0cmluZy5jYWxsKHZhbHVlKSArICddJztcbn1cblxuXG5mdW5jdGlvbiBmb3JtYXRBcnJheShjdHgsIHZhbHVlLCByZWN1cnNlVGltZXMsIHZpc2libGVLZXlzLCBrZXlzKSB7XG4gIHZhciBvdXRwdXQgPSBbXTtcbiAgZm9yICh2YXIgaSA9IDAsIGwgPSB2YWx1ZS5sZW5ndGg7IGkgPCBsOyArK2kpIHtcbiAgICBpZiAoaGFzT3duUHJvcGVydHkodmFsdWUsIFN0cmluZyhpKSkpIHtcbiAgICAgIG91dHB1dC5wdXNoKGZvcm1hdFByb3BlcnR5KGN0eCwgdmFsdWUsIHJlY3Vyc2VUaW1lcywgdmlzaWJsZUtleXMsXG4gICAgICAgICAgU3RyaW5nKGkpLCB0cnVlKSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIG91dHB1dC5wdXNoKCcnKTtcbiAgICB9XG4gIH1cbiAga2V5cy5mb3JFYWNoKGZ1bmN0aW9uKGtleSkge1xuICAgIGlmICgha2V5Lm1hdGNoKC9eXFxkKyQvKSkge1xuICAgICAgb3V0cHV0LnB1c2goZm9ybWF0UHJvcGVydHkoY3R4LCB2YWx1ZSwgcmVjdXJzZVRpbWVzLCB2aXNpYmxlS2V5cyxcbiAgICAgICAgICBrZXksIHRydWUpKTtcbiAgICB9XG4gIH0pO1xuICByZXR1cm4gb3V0cHV0O1xufVxuXG5cbmZ1bmN0aW9uIGZvcm1hdFByb3BlcnR5KGN0eCwgdmFsdWUsIHJlY3Vyc2VUaW1lcywgdmlzaWJsZUtleXMsIGtleSwgYXJyYXkpIHtcbiAgdmFyIG5hbWUsIHN0ciwgZGVzYztcbiAgZGVzYyA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3IodmFsdWUsIGtleSkgfHwgeyB2YWx1ZTogdmFsdWVba2V5XSB9O1xuICBpZiAoZGVzYy5nZXQpIHtcbiAgICBpZiAoZGVzYy5zZXQpIHtcbiAgICAgIHN0ciA9IGN0eC5zdHlsaXplKCdbR2V0dGVyL1NldHRlcl0nLCAnc3BlY2lhbCcpO1xuICAgIH0gZWxzZSB7XG4gICAgICBzdHIgPSBjdHguc3R5bGl6ZSgnW0dldHRlcl0nLCAnc3BlY2lhbCcpO1xuICAgIH1cbiAgfSBlbHNlIHtcbiAgICBpZiAoZGVzYy5zZXQpIHtcbiAgICAgIHN0ciA9IGN0eC5zdHlsaXplKCdbU2V0dGVyXScsICdzcGVjaWFsJyk7XG4gICAgfVxuICB9XG4gIGlmICghaGFzT3duUHJvcGVydHkodmlzaWJsZUtleXMsIGtleSkpIHtcbiAgICBuYW1lID0gJ1snICsga2V5ICsgJ10nO1xuICB9XG4gIGlmICghc3RyKSB7XG4gICAgaWYgKGN0eC5zZWVuLmluZGV4T2YoZGVzYy52YWx1ZSkgPCAwKSB7XG4gICAgICBpZiAoaXNOdWxsKHJlY3Vyc2VUaW1lcykpIHtcbiAgICAgICAgc3RyID0gZm9ybWF0VmFsdWUoY3R4LCBkZXNjLnZhbHVlLCBudWxsKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHN0ciA9IGZvcm1hdFZhbHVlKGN0eCwgZGVzYy52YWx1ZSwgcmVjdXJzZVRpbWVzIC0gMSk7XG4gICAgICB9XG4gICAgICBpZiAoc3RyLmluZGV4T2YoJ1xcbicpID4gLTEpIHtcbiAgICAgICAgaWYgKGFycmF5KSB7XG4gICAgICAgICAgc3RyID0gc3RyLnNwbGl0KCdcXG4nKS5tYXAoZnVuY3Rpb24obGluZSkge1xuICAgICAgICAgICAgcmV0dXJuICcgICcgKyBsaW5lO1xuICAgICAgICAgIH0pLmpvaW4oJ1xcbicpLnN1YnN0cigyKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBzdHIgPSAnXFxuJyArIHN0ci5zcGxpdCgnXFxuJykubWFwKGZ1bmN0aW9uKGxpbmUpIHtcbiAgICAgICAgICAgIHJldHVybiAnICAgJyArIGxpbmU7XG4gICAgICAgICAgfSkuam9pbignXFxuJyk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgc3RyID0gY3R4LnN0eWxpemUoJ1tDaXJjdWxhcl0nLCAnc3BlY2lhbCcpO1xuICAgIH1cbiAgfVxuICBpZiAoaXNVbmRlZmluZWQobmFtZSkpIHtcbiAgICBpZiAoYXJyYXkgJiYga2V5Lm1hdGNoKC9eXFxkKyQvKSkge1xuICAgICAgcmV0dXJuIHN0cjtcbiAgICB9XG4gICAgbmFtZSA9IEpTT04uc3RyaW5naWZ5KCcnICsga2V5KTtcbiAgICBpZiAobmFtZS5tYXRjaCgvXlwiKFthLXpBLVpfXVthLXpBLVpfMC05XSopXCIkLykpIHtcbiAgICAgIG5hbWUgPSBuYW1lLnN1YnN0cigxLCBuYW1lLmxlbmd0aCAtIDIpO1xuICAgICAgbmFtZSA9IGN0eC5zdHlsaXplKG5hbWUsICduYW1lJyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIG5hbWUgPSBuYW1lLnJlcGxhY2UoLycvZywgXCJcXFxcJ1wiKVxuICAgICAgICAgICAgICAgICAucmVwbGFjZSgvXFxcXFwiL2csICdcIicpXG4gICAgICAgICAgICAgICAgIC5yZXBsYWNlKC8oXlwifFwiJCkvZywgXCInXCIpO1xuICAgICAgbmFtZSA9IGN0eC5zdHlsaXplKG5hbWUsICdzdHJpbmcnKTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gbmFtZSArICc6ICcgKyBzdHI7XG59XG5cblxuZnVuY3Rpb24gcmVkdWNlVG9TaW5nbGVTdHJpbmcob3V0cHV0LCBiYXNlLCBicmFjZXMpIHtcbiAgdmFyIG51bUxpbmVzRXN0ID0gMDtcbiAgdmFyIGxlbmd0aCA9IG91dHB1dC5yZWR1Y2UoZnVuY3Rpb24ocHJldiwgY3VyKSB7XG4gICAgbnVtTGluZXNFc3QrKztcbiAgICBpZiAoY3VyLmluZGV4T2YoJ1xcbicpID49IDApIG51bUxpbmVzRXN0Kys7XG4gICAgcmV0dXJuIHByZXYgKyBjdXIucmVwbGFjZSgvXFx1MDAxYlxcW1xcZFxcZD9tL2csICcnKS5sZW5ndGggKyAxO1xuICB9LCAwKTtcblxuICBpZiAobGVuZ3RoID4gNjApIHtcbiAgICByZXR1cm4gYnJhY2VzWzBdICtcbiAgICAgICAgICAgKGJhc2UgPT09ICcnID8gJycgOiBiYXNlICsgJ1xcbiAnKSArXG4gICAgICAgICAgICcgJyArXG4gICAgICAgICAgIG91dHB1dC5qb2luKCcsXFxuICAnKSArXG4gICAgICAgICAgICcgJyArXG4gICAgICAgICAgIGJyYWNlc1sxXTtcbiAgfVxuXG4gIHJldHVybiBicmFjZXNbMF0gKyBiYXNlICsgJyAnICsgb3V0cHV0LmpvaW4oJywgJykgKyAnICcgKyBicmFjZXNbMV07XG59XG5cblxuLy8gTk9URTogVGhlc2UgdHlwZSBjaGVja2luZyBmdW5jdGlvbnMgaW50ZW50aW9uYWxseSBkb24ndCB1c2UgYGluc3RhbmNlb2ZgXG4vLyBiZWNhdXNlIGl0IGlzIGZyYWdpbGUgYW5kIGNhbiBiZSBlYXNpbHkgZmFrZWQgd2l0aCBgT2JqZWN0LmNyZWF0ZSgpYC5cbmZ1bmN0aW9uIGlzQXJyYXkoYXIpIHtcbiAgcmV0dXJuIEFycmF5LmlzQXJyYXkoYXIpO1xufVxuZXhwb3J0cy5pc0FycmF5ID0gaXNBcnJheTtcblxuZnVuY3Rpb24gaXNCb29sZWFuKGFyZykge1xuICByZXR1cm4gdHlwZW9mIGFyZyA9PT0gJ2Jvb2xlYW4nO1xufVxuZXhwb3J0cy5pc0Jvb2xlYW4gPSBpc0Jvb2xlYW47XG5cbmZ1bmN0aW9uIGlzTnVsbChhcmcpIHtcbiAgcmV0dXJuIGFyZyA9PT0gbnVsbDtcbn1cbmV4cG9ydHMuaXNOdWxsID0gaXNOdWxsO1xuXG5mdW5jdGlvbiBpc051bGxPclVuZGVmaW5lZChhcmcpIHtcbiAgcmV0dXJuIGFyZyA9PSBudWxsO1xufVxuZXhwb3J0cy5pc051bGxPclVuZGVmaW5lZCA9IGlzTnVsbE9yVW5kZWZpbmVkO1xuXG5mdW5jdGlvbiBpc051bWJlcihhcmcpIHtcbiAgcmV0dXJuIHR5cGVvZiBhcmcgPT09ICdudW1iZXInO1xufVxuZXhwb3J0cy5pc051bWJlciA9IGlzTnVtYmVyO1xuXG5mdW5jdGlvbiBpc1N0cmluZyhhcmcpIHtcbiAgcmV0dXJuIHR5cGVvZiBhcmcgPT09ICdzdHJpbmcnO1xufVxuZXhwb3J0cy5pc1N0cmluZyA9IGlzU3RyaW5nO1xuXG5mdW5jdGlvbiBpc1N5bWJvbChhcmcpIHtcbiAgcmV0dXJuIHR5cGVvZiBhcmcgPT09ICdzeW1ib2wnO1xufVxuZXhwb3J0cy5pc1N5bWJvbCA9IGlzU3ltYm9sO1xuXG5mdW5jdGlvbiBpc1VuZGVmaW5lZChhcmcpIHtcbiAgcmV0dXJuIGFyZyA9PT0gdm9pZCAwO1xufVxuZXhwb3J0cy5pc1VuZGVmaW5lZCA9IGlzVW5kZWZpbmVkO1xuXG5mdW5jdGlvbiBpc1JlZ0V4cChyZSkge1xuICByZXR1cm4gaXNPYmplY3QocmUpICYmIG9iamVjdFRvU3RyaW5nKHJlKSA9PT0gJ1tvYmplY3QgUmVnRXhwXSc7XG59XG5leHBvcnRzLmlzUmVnRXhwID0gaXNSZWdFeHA7XG5cbmZ1bmN0aW9uIGlzT2JqZWN0KGFyZykge1xuICByZXR1cm4gdHlwZW9mIGFyZyA9PT0gJ29iamVjdCcgJiYgYXJnICE9PSBudWxsO1xufVxuZXhwb3J0cy5pc09iamVjdCA9IGlzT2JqZWN0O1xuXG5mdW5jdGlvbiBpc0RhdGUoZCkge1xuICByZXR1cm4gaXNPYmplY3QoZCkgJiYgb2JqZWN0VG9TdHJpbmcoZCkgPT09ICdbb2JqZWN0IERhdGVdJztcbn1cbmV4cG9ydHMuaXNEYXRlID0gaXNEYXRlO1xuXG5mdW5jdGlvbiBpc0Vycm9yKGUpIHtcbiAgcmV0dXJuIGlzT2JqZWN0KGUpICYmXG4gICAgICAob2JqZWN0VG9TdHJpbmcoZSkgPT09ICdbb2JqZWN0IEVycm9yXScgfHwgZSBpbnN0YW5jZW9mIEVycm9yKTtcbn1cbmV4cG9ydHMuaXNFcnJvciA9IGlzRXJyb3I7XG5cbmZ1bmN0aW9uIGlzRnVuY3Rpb24oYXJnKSB7XG4gIHJldHVybiB0eXBlb2YgYXJnID09PSAnZnVuY3Rpb24nO1xufVxuZXhwb3J0cy5pc0Z1bmN0aW9uID0gaXNGdW5jdGlvbjtcblxuZnVuY3Rpb24gaXNQcmltaXRpdmUoYXJnKSB7XG4gIHJldHVybiBhcmcgPT09IG51bGwgfHxcbiAgICAgICAgIHR5cGVvZiBhcmcgPT09ICdib29sZWFuJyB8fFxuICAgICAgICAgdHlwZW9mIGFyZyA9PT0gJ251bWJlcicgfHxcbiAgICAgICAgIHR5cGVvZiBhcmcgPT09ICdzdHJpbmcnIHx8XG4gICAgICAgICB0eXBlb2YgYXJnID09PSAnc3ltYm9sJyB8fCAgLy8gRVM2IHN5bWJvbFxuICAgICAgICAgdHlwZW9mIGFyZyA9PT0gJ3VuZGVmaW5lZCc7XG59XG5leHBvcnRzLmlzUHJpbWl0aXZlID0gaXNQcmltaXRpdmU7XG5cbmV4cG9ydHMuaXNCdWZmZXIgPSByZXF1aXJlKCcuL3N1cHBvcnQvaXNCdWZmZXInKTtcblxuZnVuY3Rpb24gb2JqZWN0VG9TdHJpbmcobykge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKG8pO1xufVxuXG5cbmZ1bmN0aW9uIHBhZChuKSB7XG4gIHJldHVybiBuIDwgMTAgPyAnMCcgKyBuLnRvU3RyaW5nKDEwKSA6IG4udG9TdHJpbmcoMTApO1xufVxuXG5cbnZhciBtb250aHMgPSBbJ0phbicsICdGZWInLCAnTWFyJywgJ0FwcicsICdNYXknLCAnSnVuJywgJ0p1bCcsICdBdWcnLCAnU2VwJyxcbiAgICAgICAgICAgICAgJ09jdCcsICdOb3YnLCAnRGVjJ107XG5cbi8vIDI2IEZlYiAxNjoxOTozNFxuZnVuY3Rpb24gdGltZXN0YW1wKCkge1xuICB2YXIgZCA9IG5ldyBEYXRlKCk7XG4gIHZhciB0aW1lID0gW3BhZChkLmdldEhvdXJzKCkpLFxuICAgICAgICAgICAgICBwYWQoZC5nZXRNaW51dGVzKCkpLFxuICAgICAgICAgICAgICBwYWQoZC5nZXRTZWNvbmRzKCkpXS5qb2luKCc6Jyk7XG4gIHJldHVybiBbZC5nZXREYXRlKCksIG1vbnRoc1tkLmdldE1vbnRoKCldLCB0aW1lXS5qb2luKCcgJyk7XG59XG5cblxuLy8gbG9nIGlzIGp1c3QgYSB0aGluIHdyYXBwZXIgdG8gY29uc29sZS5sb2cgdGhhdCBwcmVwZW5kcyBhIHRpbWVzdGFtcFxuZXhwb3J0cy5sb2cgPSBmdW5jdGlvbigpIHtcbiAgY29uc29sZS5sb2coJyVzIC0gJXMnLCB0aW1lc3RhbXAoKSwgZXhwb3J0cy5mb3JtYXQuYXBwbHkoZXhwb3J0cywgYXJndW1lbnRzKSk7XG59O1xuXG5cbi8qKlxuICogSW5oZXJpdCB0aGUgcHJvdG90eXBlIG1ldGhvZHMgZnJvbSBvbmUgY29uc3RydWN0b3IgaW50byBhbm90aGVyLlxuICpcbiAqIFRoZSBGdW5jdGlvbi5wcm90b3R5cGUuaW5oZXJpdHMgZnJvbSBsYW5nLmpzIHJld3JpdHRlbiBhcyBhIHN0YW5kYWxvbmVcbiAqIGZ1bmN0aW9uIChub3Qgb24gRnVuY3Rpb24ucHJvdG90eXBlKS4gTk9URTogSWYgdGhpcyBmaWxlIGlzIHRvIGJlIGxvYWRlZFxuICogZHVyaW5nIGJvb3RzdHJhcHBpbmcgdGhpcyBmdW5jdGlvbiBuZWVkcyB0byBiZSByZXdyaXR0ZW4gdXNpbmcgc29tZSBuYXRpdmVcbiAqIGZ1bmN0aW9ucyBhcyBwcm90b3R5cGUgc2V0dXAgdXNpbmcgbm9ybWFsIEphdmFTY3JpcHQgZG9lcyBub3Qgd29yayBhc1xuICogZXhwZWN0ZWQgZHVyaW5nIGJvb3RzdHJhcHBpbmcgKHNlZSBtaXJyb3IuanMgaW4gcjExNDkwMykuXG4gKlxuICogQHBhcmFtIHtmdW5jdGlvbn0gY3RvciBDb25zdHJ1Y3RvciBmdW5jdGlvbiB3aGljaCBuZWVkcyB0byBpbmhlcml0IHRoZVxuICogICAgIHByb3RvdHlwZS5cbiAqIEBwYXJhbSB7ZnVuY3Rpb259IHN1cGVyQ3RvciBDb25zdHJ1Y3RvciBmdW5jdGlvbiB0byBpbmhlcml0IHByb3RvdHlwZSBmcm9tLlxuICovXG5leHBvcnRzLmluaGVyaXRzID0gcmVxdWlyZSgnaW5oZXJpdHMnKTtcblxuZXhwb3J0cy5fZXh0ZW5kID0gZnVuY3Rpb24ob3JpZ2luLCBhZGQpIHtcbiAgLy8gRG9uJ3QgZG8gYW55dGhpbmcgaWYgYWRkIGlzbid0IGFuIG9iamVjdFxuICBpZiAoIWFkZCB8fCAhaXNPYmplY3QoYWRkKSkgcmV0dXJuIG9yaWdpbjtcblxuICB2YXIga2V5cyA9IE9iamVjdC5rZXlzKGFkZCk7XG4gIHZhciBpID0ga2V5cy5sZW5ndGg7XG4gIHdoaWxlIChpLS0pIHtcbiAgICBvcmlnaW5ba2V5c1tpXV0gPSBhZGRba2V5c1tpXV07XG4gIH1cbiAgcmV0dXJuIG9yaWdpbjtcbn07XG5cbmZ1bmN0aW9uIGhhc093blByb3BlcnR5KG9iaiwgcHJvcCkge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCk7XG59XG4iXX0=
