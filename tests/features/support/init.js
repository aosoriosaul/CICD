'use strict';

const apickli = require('apickli');
const {Before, setDefaultTimeout} = require('cucumber');

Before(function() {
    this.apickli = new apickli.Apickli('https', '');

	this.apickli.addRequestHeader('Cache-Control', 'no-cache');
    this.apickli.setGlobalVariable('apigeeOrg', this.parameters.apigeeOrg);
    this.apickli.setGlobalVariable('apigeeDeveloper', this.parameters.apigeeDeveloper);
    this.apickli.setGlobalVariable('apigeeApp', this.parameters.apigeeApp);
    this.apickli.setGlobalVariable('apigeeUsername', this.parameters.apigeeUsername);
    this.apickli.setGlobalVariable('apigeePassword', this.parameters.apigeePassword);
    this.apickli.setGlobalVariable('deploymentSuffix', this.parameters.deploymentSuffix);
    this.apickli.setGlobalVariable('apigeeHost', this.parameters.apigeeHost);
    this.apickli.setGlobalVariable('apigeeDomain', this.parameters.apigeeDomain);
    this.apickli.setGlobalVariable('apigeeOauthEndpoint', this.parameters.apigeeOauthEndpoint);
    this.apickli.setGlobalVariable('accesoSimetrico', 'Do3VJxoVc9QBzMpk6/Vhh7xH0pqd+784Sva9BjNR6YY=');
    this.apickli.setGlobalVariable('codigoAutentificacionHash', 'm0sfw6fhuU8vhvJoxZ0r6ZWFZmp26kRh97eihPJntfI=');


    this.apickli.clientTLSConfig = {
        valid: {            
            key: '/home/jenkins/apigee/cert/internal-APIGEE-DEV-ALB01-616642448.us-east-1.elb.amazonaws.com.key',
            cert: '/home/jenkins/apigee/cert/internal-APIGEE-DEV-ALB01-616642448.us-east-1.elb.amazonaws.com.crt',
            ca: '/home/jenkins/apigee/cert/ca-chain.cert.pem',
        },
    };
    
});

setDefaultTimeout(60 * 1000); // this is in ms