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