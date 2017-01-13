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