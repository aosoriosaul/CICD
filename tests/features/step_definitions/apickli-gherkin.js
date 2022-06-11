/* eslint new-cap: "off", no-invalid-this: "off" */

'use strict';

const prettyJson = require('prettyjson');
const { defineSupportCode } = require('cucumber');

const stepContext = {};

/*Modulos agredos para cifrado*/
const jsonPath = require('JSONPath');
const fs = require('fs');
const crypto = require('crypto');
const constants = require('constants');
const openpgp = require("openpgp");
//const NodeRSA = require('node-rsa');

var dateFormat = require('dateformat');
const { deprecate } = require('util');
const { Console } = require('console');
var listaParamGlobal = [];
var parametersGlobal = [];
var erroresCifrado = [];

const prettyPrintJson = function (json) {
	const output = {
		stepContext,
		testOutput: json,
	};

	return prettyJson.render(output, {
		noColor: true,
	});
};

const callbackWithAssertion = function (callback, assertion) {
	if (assertion.success) {
		callback();
	} else {
		callback(prettyPrintJson(assertion));
	}
};

defineSupportCode(function ({ Before }) {
	Before(function (scenarioResult, callback) {
		// https://github.com/cucumber/cucumber-js/issues/891
		// stepContext.step = step.getName;
		// stepContext.scenario = scenario.getName;

		callback();
	});
});

defineSupportCode(function ({ Given, When, Then }) {
	Given(/^I set (.*) header to (.*)$/, function (headerName, headerValue, callback) {
		if (headerName == 'x-idAcceso') {
			var valor = this.apickli.replaceVariables(headerValue);
			console.log("<Header> = ", headerName + ": " + valor);
		}
		this.apickli.addRequestHeader(headerName, headerValue);
		callback();
	});

	Given(/^I set cookie to (.*)$/, function (cookie, callback) {
		this.apickli.addCookie(cookie);
		callback();
	});

	Given(/^I set headers to$/, function (headers, callback) {
		this.apickli.setHeaders(headers.hashes());
		callback();
	});

	Given(/^I set body to (.*)$/, function (bodyValue, callback) {
		this.apickli.setRequestBody(bodyValue);
		callback();
	});

	Given(/^I pipe contents of file (.*) to body$/, function (file, callback) {
		this.apickli.pipeFileContentsToRequestBody(file, function (error) {
			if (error) {
				callback(new Error(error));
			}

			callback();
		});
	});

	Given(/^I set query parameters to$/, function (queryParameters, callback) {
		this.apickli.setQueryParameters(queryParameters.hashes());
		callback();
	});

	Given(/^I set form parameters to$/, function (formParameters, callback) {
		this.apickli.setFormParameters(formParameters.hashes());
		callback();
	});

	Given(/^I have basic authentication credentials (.*) and (.*)$/, function (username, password, callback) {
		this.apickli.addHttpBasicAuthorizationHeader(username, password);
		callback();
	});

	Given(/^I have (.+) client TLS configuration$/, function (configurationName, callback) {
		this.apickli.setClientTLSConfiguration(configurationName, function (error) {
			if (error) {
				callback(new Error(error));
			}
			callback();
		});
	});

	/*Manda al header un valor a travez del nombre de la referencia con que fue guardada previamente*/
	Given(/^I send (.*) header to (.*)$/, function (headerName, headerParam, callback) {
		try {
			const headerValue = this.apickli.getGlobalVariable(headerParam);
			this.apickli.addRequestHeader(headerName, headerValue);
		} catch (error) { }
		callback();
	});

	/*Cifrado de parámatro header a travez de una llave publica*/
	Given(/^I use encryption algorithm (.*) and key (.*) to set (.*) header to (.*)$/, function (encryptedType, globalkey, headerName, headerValue, callback) {
		const environment = this.apickli.getGlobalVariable('localTest');
		if (environment === null || environment === false || environment === undefined) {
			const publicKey = this.apickli.getGlobalVariable(globalkey);
			const pubKeyValue = "-----BEGIN PUBLIC KEY-----\n" + publicKey + "\n-----END PUBLIC KEY-----";
			const newHeaderValue = encryptValue(headerValue, pubKeyValue, encryptedType);
			console.log("<<Header>> " + newHeaderValue);
			this.apickli.addRequestHeader(headerName, newHeaderValue);
		} else {
			this.apickli.addRequestHeader(headerName, headerValue);
		}
		callback();
	});

	/**Deprecado
	* Funcion para saber que atributos del json se van a cifrar.
	* 
	* entrada plana -> {nombre}
	* salida plana  -> ['nombre']
	* 
	* entrada con subniveles -> {beneficiarios.principales.nombre}
	* salida con subniveles  -> ['beneficiarios.principales.nombre']
	* @param {*} parametersName 
	*/
	Given(/^I need to encrypt the parameters (.*)$/, function (parametersName, callback) {
		var newObj = parametersName.substring(1, parametersName.length - 1);
		parametersGlobal = [];

		if (newObj.replace("{", "").replace("}", "").trimStart().length === 0) {
			parametersGlobal = [];
		} else if (newObj.indexOf(',') > 1) {
			parametersGlobal = newObj.split(',');
		} else {
			parametersGlobal.push(newObj);
		}

		var auxParams = [];
		for (var param of parametersGlobal) {
			if (param.includes("[*]")) {
				var nuevoParam = param.replace("[*]", "");
				auxParams.push(nuevoParam.trim());
			} else {
				auxParams.push(param.trim());
			}
		}
		parametersGlobal = auxParams;

		callback();
	});


	Given(/^I need to encrypt with (.*) as algorithm the parameters (.*)$/, function (typeAlgorithm, parametersName, callback) {
		listaParamGlobal[typeAlgorithm.toUpperCase()] = [];
		listaParamGlobal[typeAlgorithm.toUpperCase()] = createList(parametersName);

		callback();
	});

	function createList(listaParam) {
		var newObj = listaParam.substring(1, listaParam.length - 1);
		parametersGlobal = [];

		if (newObj.replace("{", "").replace("}", "").trimStart().length === 0) {
			parametersGlobal = [];
		} else if (newObj.indexOf(',') > 1) {
			parametersGlobal = newObj.split(',');
		} else {
			parametersGlobal.push(newObj);
		}

		var auxParams = [];
		for (var param of parametersGlobal) {
			if (param.includes("[*]")) {
				var nuevoParam = param.replace("[*]", "");
				auxParams.push(nuevoParam.trim());
			} else {
				auxParams.push(param.trim());
			}
		}
		return auxParams;
	};

	/**
	 * Funcion para :
	 * validar si se cifra o no con base al ambiente corriendo.
	 * valida si es un json plano o con subniveles
	 * hace el cifrado de los parametros seleccionados
	 * @param {*} encryptedType     -> tipo de cifrado requerido
	 * @param {*} globalkey         -> llave publica
	 * @param {*} bodyValue         -> json de entrada para cifrar
	 */
	Given(/^I use the encryption algorithm (.*) and the key (.*) for prepare a body as (.*)$/, function (encryptedType, globalkey, bodyValue, callback) {
		const publicKey = this.apickli.getGlobalVariable(globalkey);
		const environment = this.apickli.getGlobalVariable('localTest');
		var pubKeyValue = "-----BEGIN PUBLIC KEY-----\n" + publicKey + "\n-----END PUBLIC KEY-----";
		var objJSON = JSON.parse(bodyValue);
		var app = this.apickli;

		//Código importante al pasar el valor a donde se requiera
		bodyValue = JSON.stringify(objJSON, function replacer(key, value) {
			if (value instanceof Object) {
				return value;
			} else if (key.length > 0) {
				if (isString(value)) {
					value = app.replaceVariables(JSON.stringify(value));
					return value.toString().split("\"").join("");
				}
				else {
					return value;
				}
			}
			else {
				return value;
			}
		});

		parametersGlobal = listaParamGlobal["RSA"];
		if (environment === null || environment === false || environment === undefined) {
			console.log("ENCRIPTA =>")
			if (parametersGlobal.length > 0) {
				parametersGlobal.forEach(function (param) {
					objJSON = JSON.parse(bodyValue);
					var paramPoint = param.split('.');
					bodyValue = findNodesJSON(objJSON, objJSON, paramPoint, pubKeyValue, encryptedType);
				});
			} else {
				objJSON = JSON.parse(bodyValue);
				bodyValue = JSON.stringify(objJSON, function replacer(key, value) {
					if (value instanceof Object) {
						return value;
					} else if (key.length > 0) {
						return encryptValue(JSON.stringify(value), pubKeyValue, encryptedType);
					} else {
						return value;
					}
				});
			}
		} else {
			console.log('NO ENCRIPTA =>')
		}
		console.log("bodyValue final => ", bodyValue);
		if (erroresCifrado.length > 1)
			console.log(">>Campos no cifrados => ", erroresCifrado);
		this.apickli.setRequestBody(bodyValue);
		callback();
	});

	function isString(value) {
		return typeof value === 'string' || value instanceof String;
	}

	/**
	 * Funcion para recorrer el objeto json y cifrar todos los valores del atributo seleccionado.
	 * @param {*} strJSON       -> json de entrada para comparar
	 * @param {*} bdyJSON       -> json de entrada para cifrar
	 * @param {*} paramPoints   -> path donde se encuentra el atributo que se va a cifrar
	 * @param {*} pubKey        -> llave publica
	 * @param {*} tipoCifrado   -> tipo de cifrado requerido
	 */
	function findNodesJSON(strJSON, bdyJSON, paramPoints, pubKey, tipoCifrado) {
		if (paramPoints.length > 1) {
			var bodyTmp = JSON.stringify(bdyJSON[paramPoints[0]]);
			if (bodyTmp === undefined) {
				//console.log("---------->", bodyTmp);
				if (Array.isArray(bdyJSON)) {
					for (var i in bdyJSON) {
						var copyJSON = JSON.stringify(strJSON);
						var prevBdy = JSON.stringify(bdyJSON[i]);
						bdyJSON[i] = JSON.stringify(bdyJSON[i], function replacer(pkey, pvalue) {
							if (pvalue instanceof Object)
								return pvalue;
							/*
							################### Soluciona el error  data too large for key size ###################3
							*/
							if (pkey.trimStart() === paramPoints[paramPoints.length - 1] && pvalue !=null && pvalue.length < 100)
								pvalue = encryptValue(JSON.stringify(pvalue), pubKey, tipoCifrado);
							return pvalue;
						});
						copyJSON = copyJSON.replace(prevBdy, bdyJSON[i]);
						strJSON = JSON.parse(copyJSON);
					}
					return JSON.stringify(strJSON);
				}
			}
			if (bodyTmp === undefined) {
				erroresCifrado.push("El nodo: " + paramPoints[0] + " no fue encontrado");
				return JSON.stringify(strJSON);
			}
			paramPoints.shift();
			return findNodesJSON(strJSON, JSON.parse(bodyTmp), paramPoints, pubKey, tipoCifrado);

		} else if (paramPoints.length === 1) {
			if (Array.isArray(bdyJSON)) {
				for (var i in bdyJSON) {
					if (bdyJSON[i][paramPoints[0]] !== undefined) {
						var prevBdy = JSON.stringify(bdyJSON);
						var bjson = JSON.stringify(strJSON);
						//console.log(bdyJSON[i][paramPoints[0]]);
						bdyJSON[i][paramPoints[0]] = encryptValue(JSON.stringify(bdyJSON[i][paramPoints[0]]), pubKey, tipoCifrado);
						bjson = bjson.replace(prevBdy, JSON.stringify(bdyJSON));
						strJSON = JSON.parse(bjson);
					} else {
						var msgError = "El campo: " + paramPoints[0] + " no fue encontrado";
						if (!erroresCifrado.includes(msgError))
							erroresCifrado.push(msgError);
					}
				}
			} else if (bdyJSON instanceof Object) {
				if (bdyJSON[paramPoints[0]] === undefined) {
					erroresCifrado.push("El campo: " + paramPoints[0] + " no fue encontrado");
				} else {
					console.log("-----------------> nodo error: ", paramPoints[0]);
					var prevBdy = JSON.stringify(bdyJSON);
					bdyJSON[paramPoints[0]] = encryptValue(JSON.stringify(bdyJSON[paramPoints[0]]), pubKey, tipoCifrado);
					var bjson = JSON.stringify(strJSON);
					bjson = bjson.replace(prevBdy, JSON.stringify(bdyJSON));
					strJSON = JSON.parse(bjson);
				}
			}
		}
		return JSON.stringify(strJSON);
	};

	/**
	 * Funcion para cifrar el valor con base al tipo de cifrado seleccionado
	 * @param {*} paramValue        -> valor del atributo json que se va a cifrar
	 * @param {*} pubKey            -> llave publica
	 * @param {*} encryptedType     -> tipo de cifrado requerido
	 */
	function encryptValue(paramValue, pubKey, encryptedType) {
		var padd = "";
		if (encryptedType === "RSA_PKCS1_PADDING") {
			padd = crypto.constants.RSA_PKCS1_PADDING;
		} else if (encryptedType === "RSA_NO_PADDING") {
			padd = crypto.constants.RSA_NO_PADDING;
		} else if (encryptedType === "RSA_PKCS1_OAEP_PADDING") {
			padd = crypto.constants.RSA_PKCS1_OAEP_PADDING;
		} else if (encryptedType === "RSA_ECB_OAEPWithSHA") {
			var key = new NodeRSA();
			key.importKey(pubKey, "pkcs8-public");
			var encrypted = key.encrypt(paramValue.toString().split("\"").join(""), "base64");

			return encrypted;
		}

		//Se agrega try catch para controlar errores de cifrado
		try {
			//Se modifica instruccion para eliminar comilla
			var buffer = Buffer.from(paramValue.toString().split("\"").join(""), 'utf8');
			var encrypted = crypto.publicEncrypt({ key: pubKey, padding: padd }, buffer);
			return encrypted.toString("base64");
		} catch(Error) {
			console.log("tryCatch: no se pudo cifrar", paramValue)
			return paramValue;
		}
	};


	/*Se obtiene la fecha actual con formato especificado */
	Given(/^I build a date whith format (.*) and store the value as (.*) in global scope$/, function (strFormat, globalName, callback) {
		var now = new Date();
		const fechaFormateada = dateFormat(now, strFormat);
		this.apickli.setGlobalVariable(globalName.toString(), fechaFormateada);
		callback();
	});

	/**
	 * Funcion para :
	 * Cifrado PGP del campos en el header llave publica
	 * @param {*} globalkey     -> llave publica
	 * @param {*} headerName	-> nombre del campo header
	 * @param {*} headerValue	-> valor de campo para cifrar
	 */
	Given(/^I encrypt PGP with key (.*) to set (.*) header to (.*)$/, function (globalkey, headerName, headerValue, callback) {
		const environment = this.apickli.getGlobalVariable('localTest');
		const publicKey = this.apickli.getGlobalVariable(globalkey);

		if (environment === null || environment === false || environment === undefined) {
			encryptPGP(publicKey, headerName, headerValue, this.apickli, callback);
		}
		this.apickli.addRequestHeader(headerName, headerValue);
		callback();
	});

	async function encryptPGP(publicKey, headerName, headerValue, apiko, callback) {
		const valor = await (async () => {
			await openpgp.initWorker({});

			const { data: encrypted } = await openpgp.encrypt({
				message: openpgp.message.fromText(headerValue),
				publicKeys: (await openpgp.key.readArmored(publicKey)).keys,
				numBits: 2048,
				armor: true
			});
			return cleanResponse(encrypted);
		})();

		console.log("(Header) ==>" + headerName + ": " + valor);
		apiko.addRequestHeader(headerName, valor);
		setTimeout(function () { callback(); }, 300);
	};

	function cleanResponse(encryptedCmp) {
		var arrEncrypt = encryptedCmp.split("\n");
		for (var index = 0; index < 4; index++) {
			encryptedCmp = encryptedCmp.replace(arrEncrypt[index], "");
		}
		encryptedCmp = encryptedCmp.replace(arrEncrypt[arrEncrypt.length - 2], "");
		return encryptedCmp.replace(/(\r\n|\n|\r)/gm, "");
	};


	/*Cifrado PGP del cuerpo JSON a través de una llave publica*/
	Given(/^I encrypt PGP params with key (.*) and JSON (.*)$/, function (globalkey, bodyValue, callback) {
		const environment = this.apickli.getGlobalVariable('localTest');
		var timeFunction = 3000;

		if (environment === null || environment === false || environment === undefined) {
			const publicKey = this.apickli.getGlobalVariable(globalkey);
			encryptJSONPGP(bodyValue, publicKey);
		} else {
			timeFunction = 0;
		}
		console.log("-body PGP-: ", bodyValue);
		setTimeout(function () { callback(); }, timeFunction);
	});

	async function encryptJSONPGP(bodyValue, publicKey) {
		var objJSON = JSON.parse(bodyValue);

		var data = new Uint8Array(Buffer.from(""));
		var dir = './requestJson';
		if (!fs.existsSync(dir)) {
			fs.mkdirSync(dir);
		}
		fs.writeFile('./requestJson/jsonScript.txt', data, (err) => {
			if (err) throw err;
			console.log('The file has not been saved!');
		});
		bodyValue = JSON.stringify(objJSON, function replacer(key, value) {
			if (value instanceof Object) {
				return value;
			} else if (key.length > 0) {
				(async () => {
					await openpgp.initWorker({});

					const { data: encrypted } = await openpgp.encrypt({
						message: openpgp.message.fromText(value),
						publicKeys: (await openpgp.key.readArmored(publicKey)).keys,
						numBits: 2048,
						armor: true
					});

					const data = new Uint8Array(Buffer.from(key + ":" + cleanResponse(encrypted) + ","));
					fs.appendFile('./requestJson/jsonScript.txt', data, (err) => {
						if (err) throw err;
						console.log('The file has been saved!');
					});
				})();
				return value;
			} else {
				return value;
			}
		});
	}

	Given(/^I replace encrypt body in the JSON (.*)$/, function (bodyValue, callback) {
		const environment = this.apickli.getGlobalVariable('localTest');
		var objJSON = "";

		if (environment === null || environment === false || environment === undefined) {
			const textJSON = fs.readFileSync('./requestJson/jsonScript.txt', 'utf8')

			const elementLst = textJSON.split(",");

			elementLst.forEach(function (elementString) {
				var elementValue = elementString.trimStart().split(":");
				objJSON = JSON.parse(bodyValue);
				var paramPoint = elementValue[0].split('.');
				bodyValue = findNodesValueJSON(objJSON, objJSON, paramPoint, elementValue[1]);
			});
			console.log("(JSON cifrado)==> " + bodyValue);
		} else {
			console.log("(JSON claro)==> " + bodyValue);
		}
		this.apickli.setRequestBody(bodyValue);
		callback();
	});

	function findNodesValueJSON(strJSON, bdyJSON, paramPoints, value) {
		if (paramPoints.length > 1) {
			var bodyTmp = JSON.stringify(bdyJSON[paramPoints[0]]);
			if (bodyTmp === undefined) {
				erroresCifrado.push("El nodo: " + paramPoints[0] + " no fue encontrado");
				return JSON.stringify(strJSON);
			}
			paramPoints.shift();
			return findNodesValueJSON(strJSON, JSON.parse(bodyTmp), paramPoints, value);

		} else if (paramPoints.length === 1) {
			if (Array.isArray(bdyJSON)) {
				for (var i in bdyJSON) {
					if (bdyJSON[i][paramPoints[0]] !== undefined) {
						var prevBdy = JSON.stringify(bdyJSON);
						var bjson = JSON.stringify(strJSON);
						bdyJSON[i][paramPoints[0]] = value;
						bjson = bjson.replace(prevBdy, JSON.stringify(bdyJSON));
						strJSON = JSON.parse(bjson);
					} else {
						var msgError = "El campo: " + paramPoints[0] + " no fue encontrado";
						if (!erroresCifrado.includes(msgError))
							erroresCifrado.push(msgError);
					}
				}
			} else if (bdyJSON instanceof Object) {
				if (bdyJSON[paramPoints[0]] === undefined) {
					erroresCifrado.push("El campo: " + paramPoints[0] + " no fue encontrado");
				} else {
					var prevBdy = JSON.stringify(bdyJSON);
					bdyJSON[paramPoints[0]] = value;
					var bjson = JSON.stringify(strJSON);
					bjson = bjson.replace(prevBdy, JSON.stringify(bdyJSON));
					strJSON = JSON.parse(bjson);
				}
			}
		}
		return JSON.stringify(strJSON);
	};

	/**
	 * Función que recibe un multipart/form-data
	 * @param {*} formParameters 
	 */
	Given(/^I set form-data parameters to$/, function (formParameters, callback) {
		const self = this.apickli;
		const paramsObject = {};
		var formParams = formParameters.hashes();

		formParams.forEach(function (f) {
			const formParameterName = self.replaceVariables(f.parameter);
			const filepath = self.replaceVariables(f.value);
			var formParameterValue = null;

			if (filepath.includes('.jpeg') || filepath.includes('.pdf') || filepath.includes('.png') || filepath.includes('.tiff')) {
				if (!fs.existsSync(filepath)) {
					callback(new Error('El archivo no existe'));
				}
				fs.readFile(filepath, 'utf8', function (err, data) {
					if (err) {
						callback(err);
					} else {
						formParameterValue = self.replaceVariables(data);
					}
				});
			} else {
				formParameterValue = self.replaceVariables(f.value);
			}
			paramsObject[formParameterName] = formParameterValue;
		});

		this.apickli.formParameters = paramsObject;
		callback();

	});

	Given(/^I reencrypt the previous JSON with AES algorithm and the key (.*) and hash (.*)$/, function (aeskey, hmacKey, callback) {
		const aesK = this.apickli.getGlobalVariable(aeskey);
		const hmack = this.apickli.getGlobalVariable(hmacKey);
		var bodyValue = this.apickli.requestBody
		var objJSON = JSON.parse(bodyValue);
		const environment = this.apickli.getGlobalVariable('localTest');


		parametersGlobal = listaParamGlobal["AES"];
		if (environment === null || environment === false || environment === undefined) {
			if (parametersGlobal !== undefined) {
				if (parametersGlobal.length > 0) {
					parametersGlobal.forEach(function (param) {
						console.log('->------------------>>>', param);
						objJSON = JSON.parse(bodyValue);
						var paramPoint = param.split('.');
						bodyValue = findNodesJSONByAES(objJSON, objJSON, paramPoint, aesK, hmack);
					});
				}
				console.log("bodyValue final => ", bodyValue);
				if (erroresCifrado.length > 1)
					console.log(">>Campos no cifrados AES=> ", erroresCifrado);
			}
		}
		this.apickli.setRequestBody(bodyValue);
		callback();
	});

	/**
	 * Funcion para recorrer el objeto json y cifrar todos los valores del atributo seleccionado.
	 * @param {*} strJSON       -> json de entrada para comparar
	 * @param {*} bdyJSON       -> json de entrada para cifrar
	 * @param {*} paramPoints   -> path donde se encuentra el atributo que se va a cifrar
	 * @param {*} pubKey        -> llave publica
	 * @param {*} tipoCifrado   -> tipo de cifrado requerido
	 */
	function findNodesJSONByAES(strJSON, bdyJSON, paramPoints, aesKey, hmacKey) {
		if (paramPoints.length > 1) {
			var bodyTmp = JSON.stringify(bdyJSON[paramPoints[0]]);

			if (bodyTmp === undefined) {
				if (Array.isArray(bdyJSON)) {
					for (var i in bdyJSON) {
						var copyJSON = JSON.stringify(strJSON);
						var prevBdy = JSON.stringify(bdyJSON[i]);
						bdyJSON[i] = JSON.stringify(bdyJSON[i], function replacer(pkey, pvalue) {
							if (pvalue instanceof Object)
								return pvalue;
							if (pkey.trimStart() === paramPoints[paramPoints.length - 1])
								pvalue = encryptAes(JSON.stringify(pvalue), aesKey, hmacKey);
							return pvalue;
						});
						copyJSON = copyJSON.replace(prevBdy, bdyJSON[i]);
						strJSON = JSON.parse(copyJSON);
					}
					return JSON.stringify(strJSON);
				}
			}
			if (bodyTmp === undefined) {
				erroresCifrado.push("El nodo: " + paramPoints[0] + " no fue encontrado");
				return JSON.stringify(strJSON);
			}
			paramPoints.shift();
			return findNodesJSONByAES(strJSON, JSON.parse(bodyTmp), paramPoints, aesKey, hmacKey);

		} else if (paramPoints.length === 1) {
			if (Array.isArray(bdyJSON)) {
				for (var i in bdyJSON) {
					if (bdyJSON[i][paramPoints[0]] !== undefined) {
						var prevBdy = JSON.stringify(bdyJSON);
						var bjson = JSON.stringify(strJSON);
						//console.log(bdyJSON[i][paramPoints[0]]);
						bdyJSON[i][paramPoints[0]] = encryptAes(JSON.stringify(bdyJSON[i][paramPoints[0]]), aesKey, hmacKey);
						bjson = bjson.replace(prevBdy, JSON.stringify(bdyJSON));
						strJSON = JSON.parse(bjson);
					} else {
						var msgError = "El campo: " + paramPoints[0] + " no fue encontrado";
						if (!erroresCifrado.includes(msgError))
							erroresCifrado.push(msgError);
					}
				}
			} else if (bdyJSON instanceof Object) {
				if (bdyJSON[paramPoints[0]] === undefined) {
					erroresCifrado.push("El campo: " + paramPoints[0] + " no fue encontrado");
				} else {
					var prevBdy = JSON.stringify(bdyJSON);
					bdyJSON[paramPoints[0]] = encryptAes(JSON.stringify(bdyJSON[paramPoints[0]]), aesKey, hmacKey);
					var bjson = JSON.stringify(strJSON);
					bjson = bjson.replace(prevBdy, JSON.stringify(bdyJSON));
					strJSON = JSON.parse(bjson);
				}
			}
		}
		return JSON.stringify(strJSON);
	};

	function encryptAes(plainText, aesK, hmack) {
		var datoAcifrar = plainText.replace(/['"]+/g, '');
		var aesKey = Buffer.from(aesK, "utf8");
		aesKey = Buffer.from(aesK, "base64");
		var aesHmac = Buffer.from(hmack, 'utf8');
		aesHmac = Buffer.from(aesHmac, "base64");
		const iv = crypto.randomBytes(16);

		const cipher = crypto.createCipheriv(getAlgorithm(aesKey), aesKey, iv);
		let cipherText = Buffer.concat([cipher.update(Buffer.from(datoAcifrar, "utf8")), cipher.final()]);
		const iv_cipherText = Buffer.concat([iv, cipherText]);
		var hmac = crypto.createHmac('SHA256', Buffer.from(hmack, 'base64')).update(iv_cipherText).digest();
		const iv_cipherText_hmac = Buffer.concat([iv_cipherText, hmac]);
		const iv_cipherText_hmac_base64 = iv_cipherText_hmac.toString("base64");
		//console.log('<Cifrado AES>: ', iv_cipherText_hmac_base64);

		return iv_cipherText_hmac_base64;
	}

	function getAlgorithm(keyBase64) {
		var key = Buffer.from(keyBase64, 'base64');
		switch (key.length) {
			case 16:
				return 'aes-128-cbc';
			case 32:
				return 'aes-256-cbc';
		}
		throw new Error('Invalid key length: ' + key.length);
	}

	Given(/^I use the algorithm AES and the accesskey (.*) and hash (.*) for prepare a body as (.*)$/, function (aeskey, hmacKey, bodyValue, callback) {
		const environment = this.apickli.getGlobalVariable('localTest');
		const aesK = this.apickli.getGlobalVariable(aeskey);
		const hmack = this.apickli.getGlobalVariable(hmacKey);

		var objJSON = JSON.parse(bodyValue);
		parametersGlobal = listaParamGlobal["AES"];

		if (environment === null || environment === false || environment === undefined) {
			if (parametersGlobal !== undefined) {
				if (parametersGlobal.length > 0) {
					parametersGlobal.forEach(function (param) {
						objJSON = JSON.parse(bodyValue);
						var paramPoint = param.split('.');
						bodyValue = findNodesJSONByAES(objJSON, objJSON, paramPoint, aesK, hmack);
					});
				}
				console.log("bodyValue final => ", bodyValue);
				if (erroresCifrado.length > 1)
					console.log(">>Campos no cifrados AES=> ", erroresCifrado);
			}
		}
		this.apickli.setRequestBody(bodyValue);
		callback();
	});


	When(/^I GET (.*)$/, function (resource, callback) {
		this.apickli.get(resource, function (error, response) {
			if (error) {
				callback(new Error(error));
			}

			callback();
		});
	});

	When(/^I POST to (.*)$/, function (resource, callback) {
		this.apickli.post(resource, function (error, response) {
			if (error) {
				callback(new Error(error));
			}

			callback();
		});
	});

	When(/^I PUT (.*)$/, function (resource, callback) {
		this.apickli.put(resource, function (error, response) {
			if (error) {
				callback(new Error(error));
			}

			callback();
		});
	});

	When(/^I DELETE (.*)$/, function (resource, callback) {
		this.apickli.delete(resource, function (error, response) {
			if (error) {
				callback(new Error(error));
			}

			callback();
		});
	});

	When(/^I PATCH (.*)$/, function (resource, callback) {
		this.apickli.patch(resource, function (error, response) {
			if (error) {
				callback(new Error(error));
			}

			callback();
		});
	});

	When(/^I request OPTIONS for (.*)$/, function (resource, callback) {
		this.apickli.options(resource, function (error, response) {
			if (error) {
				callback(new Error(error));
			}

			callback();
		});
	});

	/*Cifrado de queryParam*/
	When(/^with encryption algorithm (.*) and the key (.*) I GET (.*)$/, function (encryptedType, globalkey, resource, callback) {
		const publicKey = this.apickli.getGlobalVariable(globalkey);
		var pubKeyValue = "-----BEGIN PUBLIC KEY-----\n" + publicKey + "\n-----END PUBLIC KEY-----";

		if (resource.includes("?") && parametersGlobal.length > 0) {
			parametersGlobal.forEach(function (paramEncrypt) {
				resource = findQueryParamValue(resource, paramEncrypt, pubKeyValue, encryptedType);

			});
		}

		//console.log("------->"+resource);
		this.apickli.get(resource, function (error, response) {
			if (error) {
				callback(new Error(error));
			}

			callback();
		});
	});

	function findQueryParamValue(resource, paramEncrypt, pubKey, tipoCifrado) {
		var nwStr = resource.split("?");
		var newQP = nwStr[0] + "?";
		var arrParams = nwStr[1].split("&");

		arrParams.forEach(function (param) {
			var keyValue = param.split("=");
			if (keyValue[0] === paramEncrypt.trimStart())
				param = keyValue[0] + "=" + encryptValue(keyValue[1], pubKey, tipoCifrado);

			newQP = newQP.concat(param);

			if (arrParams[arrParams.length - 1] !== param)
				newQP = newQP.concat("&");
		});

		return newQP;
	};
	/*Fin de Cifrado de queryParam*/

	Then(/^response header (.*) should exist$/, function (header, callback) {
		const assertion = this.apickli.assertResponseContainsHeader(header);
		callbackWithAssertion(callback, assertion);
	});

	Then(/^response header (.*) should not exist$/, function (header, callback) {
		const assertion = this.apickli.assertResponseContainsHeader(header);
		assertion.success = !assertion.success;
		callbackWithAssertion(callback, assertion);
	});

	Then(/^response body should be valid (xml|json)$/, function (contentType, callback) {
		const assertion = this.apickli.assertResponseBodyContentType(contentType);
		callbackWithAssertion(callback, assertion);
	});

	Then(/^response code should be (.*)$/, function (responseCode, callback) {
		const assertion = this.apickli.assertResponseCode(responseCode);
		callbackWithAssertion(callback, assertion);
	});

	Then(/^response code should not be (.*)$/, function (responseCode, callback) {
		const assertion = this.apickli.assertResponseCode(responseCode);
		assertion.success = !assertion.success;
		callbackWithAssertion(callback, assertion);
	});

	Then(/^response header (.*) should be (.*)$/, function (header, expression, callback) {
		const assertion = this.apickli.assertHeaderValue(header, expression);
		callbackWithAssertion(callback, assertion);
	});

	Then(/^response header (.*) should not be (.*)$/, function (header, expression, callback) {
		const assertion = this.apickli.assertHeaderValue(header, expression);
		assertion.success = !assertion.success;
		callbackWithAssertion(callback, assertion);
	});

	Then(/^response body should contain (.*)$/, function (expression, callback) {
		const assertion = this.apickli.assertResponseBodyContainsExpression(expression);
		callbackWithAssertion(callback, assertion);
	});

	Then(/^response body should not contain (.*)$/, function (expression, callback) {
		const assertion = this.apickli.assertResponseBodyContainsExpression(expression);
		assertion.success = !assertion.success;
		callbackWithAssertion(callback, assertion);
	});

	Then(/^response body path (.*) should be (((?!of type).*))$/, function (path, value, callback) {
		const assertion = this.apickli.assertPathInResponseBodyMatchesExpression(path, value);
		callbackWithAssertion(callback, assertion);
	});

	Then(/^response body path (.*) should not be (((?!of type).+))$/, function (path, value, callback) {
		const assertion = this.apickli.assertPathInResponseBodyMatchesExpression(path, value);
		assertion.success = !assertion.success;
		callbackWithAssertion(callback, assertion);
	});

	Then(/^response body path (.*) should be of type array$/, function (path, callback) {
		const assertion = this.apickli.assertPathIsArray(path);
		callbackWithAssertion(callback, assertion);
	});

	Then(/^response body path (.*) should be of type array with length (.*)$/, function (path, length, callback) {
		const assertion = this.apickli.assertPathIsArrayWithLength(path, length);
		callbackWithAssertion(callback, assertion);
	});

	Then(/^response body should be valid according to schema file (.*)$/, function (schemaFile, callback) {
		this.apickli.validateResponseWithSchema(schemaFile, function (assertion) {
			callbackWithAssertion(callback, assertion);
		});
	});

	Then(/^response body should be valid according to openapi description (.*) in file (.*)$/, function (definitionName, swaggerSpecFile, callback) {
		this.apickli.validateResponseWithSwaggerSpecDefinition(definitionName, swaggerSpecFile, function (assertion) {
			callbackWithAssertion(callback, assertion);
		});
	});

	Then(/^I store the value of body path (.*) as access token$/, function (path, callback) {
		this.apickli.setAccessTokenFromResponseBodyPath(path);
		callback();
	});

	When(/^I set bearer token$/, function (callback) {
		this.apickli.setBearerToken();
		callback();
	});

	Given(/^I store the raw value (.*) as (.*) in scenario scope$/, function (value, variable, callback) {
		this.apickli.storeValueInScenarioScope(variable, value);
		callback();
	});

	Then(/^I store the value of response header (.*) as (.*) in global scope$/, function (headerName, variableName, callback) {
		this.apickli.storeValueOfHeaderInGlobalScope(headerName, variableName);
		callback();
	});

	Then(/^I store the value of body path (.*) as (.*) in global scope$/, function (path, variableName, callback) {
		this.apickli.storeValueOfResponseBodyPathInGlobalScope(path, variableName);
		callback();
	});

	Then(/^I store the value of response header (.*) as (.*) in scenario scope$/, function (name, variable, callback) {
		this.apickli.storeValueOfHeaderInScenarioScope(name, variable);
		callback();
	});

	Then(/^I store the value of body path (.*) as (.*) in scenario scope$/, function (path, variable, callback) {
		this.apickli.storeValueOfResponseBodyPathInScenarioScope(path, variable);
		callback();
	});

	Then(/^value of scenario variable (.*) should be (.*)$/, function (variableName, variableValue, callback) {
		if (this.apickli.assertScenarioVariableValue(variableName, variableValue)) {
			callback();
		} else {
			callback(new Error('value of variable ' + variableName + ' isn\'t equal to ' + variableValue));
		}
	});

	/**Nuevo
	 * Funcion para :
	 * validar si se descifra o no con base al ambiente corriendo.
	 * descifra los valores de los atributos requeridos del objeto json.
	 * @param {*} globalkey         -> llave privada
	 * @param {*} path              -> path del objeto json donde se encuentra el valor a descifrar
	 * @param {*} encryptedType     -> tipo de descifrado que se requieire
	 * @param {*} value             -> expresion regular o valor en claro que se espera despues de descifrar
	 */
	Then(/^deciphering with the key (.*) the response field (.*) and (.*) as encryption algorithm should be (((?!of type).*))$/, function (globalkey, path, encryptedType, value, callback) {
		const prvKey = "-----BEGIN PRIVATE KEY-----\n" + this.apickli.getGlobalVariable(globalkey) + "\n-----END PRIVATE KEY-----";
		const environment = this.apickli.getGlobalVariable('localTest');
		const contentType = this.apickli.getResponseObject().body;
		const headers = this.apickli.getResponseObject().headers;
		const contentJson = JSON.parse(contentType);
		const evalResult = jsonPath({ resultType: 'all' }, path, contentJson);
		var strValue = null;

		if (environment === null || environment === false || environment === undefined) {
			path = this.apickli.replaceVariables(path);
			if (evalResult[0] !== undefined && evalResult[0].value !== undefined) {
				var rest = evalResult[0].value;
				var padd = "";
				if (encryptedType === "RSA_PKCS1_PADDING") {
					padd = crypto.constants.RSA_PKCS1_PADDING;
				} else if (encryptedType === "RSA_NO_PADDING") {
					padd = crypto.constants.RSA_NO_PADDING;
				} else if (encryptedType === "RSA_PKCS1_OAEP_PADDING") {
					padd = crypto.constants.RSA_PKCS1_OAEP_PADDING;
				}

				if (encryptedType === "RSA_ECB_OAEPWithSHA") {
					var pkey = new NodeRSA();
					pkey.importKey(prvKey, "pkcs8-private");
					var descryptValue = pkey.decrypt(rest, 'utf-8');
					strValue = descryptValue;
				} else {
					try {
						var msg = new Buffer.from(rest, "base64");
						var descryptValue = crypto.privateDecrypt({ key: prvKey, padding: padd }, msg);
						strValue = descryptValue.toString().split('"').join("");
					} catch (error) {
						strValue = "Error Descifrado: " + error;
					}
				}
			}
		} else {
			strValue = evalResult[0].value;
		}

		const regExpObject = new RegExp(value);
		const successExp = regExpObject.test(strValue);
		const assertion = getAssertionResultado(successExp, strValue, value, contentType, headers);

		callbackWithAssertion(callback, assertion);
	});

	const getAssertionResultado = function (success, expected, actual, contentBody, headers) {
		return {
			success,
			expected,
			actual,
			response: {
				statusCode: 400,
				headers: headers,
				body: contentBody
			}
		};
	};

	/**
	 * Funcion para :
	 * descifra los valores de los atributos requeridos del objeto json. 
	 * @param {*} pgpPrivateKey         -> llave privada
	 * @param {*} pgpSecurityKey        -> PGP-Key Password
	 * @param {*} path         			-> path del objeto json donde se encuentra el valor a descifrar
	 * @param {*} value         		-> expresion regular o valor en claro que se espera despues de descifrar
	 */
	Then(/^deciphering PGP with key (.*) using passphrase (.*) the response body path (.*) should be (((?!of type).*))$/, function (pgpPrivateKey, pgpSecurityKey, path, value, callback) {
		const privateKey = this.apickli.getGlobalVariable(pgpPrivateKey);
		const clavePrivada = this.apickli.getGlobalVariable(pgpSecurityKey);
		const environment = this.apickli.getGlobalVariable('localTest');

		if (environment === false || environment === false || environment === undefined) {
			decipherPGP(privateKey, clavePrivada, path, this.apickli, value, callback);
		} else {
			const assertion = this.apickli.assertPathInResponseBodyMatchesExpression(path, value);
			callbackWithAssertion(callback, assertion);
		}
	});

	async function decipherPGP(privateKeyArmored, pgpSecurityKey, path, thApickli, valuePath, callback) {
		const contentType = thApickli.getResponseObject().body;
		const headers = thApickli.getResponseObject().headers;
		const contentJson = JSON.parse(contentType);
		const evalResult = jsonPath({ resultType: 'all' }, path, contentJson);
		var strValue = evalResult[0].value;
		var messageData = "-----BEGIN PGP MESSAGE-----\n\n" + strValue + "\n-----END PGP MESSAGE-----";

		//console.log("reponse privateKey: ", privateKeyArmored);
		console.log("reponse frase: ", pgpSecurityKey);
		console.log("reponse path: ", messageData);
		var valorDecrypted = await (async () => {
			await openpgp.initWorker();
			openpgp.config.ignore_mdc_error = true;
			const { keys: [privateKey] } = await openpgp.key.readArmored(privateKeyArmored);
			await privateKey.decrypt(pgpSecurityKey);

			const { data: decrypted } = await openpgp.decrypt({
				message: await openpgp.message.readArmored(messageData),
				privateKeys: [privateKey]

			});
			return decrypted;
		})();

		console.log("<<valor Descifrado>>: ", valorDecrypted);
		const regExpObject = new RegExp(valuePath);
		const successExp = regExpObject.test(valorDecrypted);
		const assertion = getAssertionResultado(successExp, valorDecrypted, valuePath, contentType, headers);
		setTimeout(function () { callbackWithAssertion(callback, assertion); }, 3000);

	}

	Then(/^I store the deciphering value encrypted with AES of body path (.*) as (.*) in global scope$/, function (path, variableName, callback) {
		const aesK = this.apickli.getGlobalVariable('accesoSimetrico');
		const hmack = this.apickli.getGlobalVariable('codigoAutentificacionHash');

		//console.log("ACCESO SIMETRICO XXX:", aesK);
		//console.log("HASH XXX:", hmack);

		path = this.apickli.replaceVariables(path);

		const contentType = this.apickli.getResponseObject().body;
		const headers = this.apickli.getResponseObject().headers;
		const contentJson = JSON.parse(contentType);
		const evalResult = jsonPath({ resultType: 'all' }, path, contentJson);
		var rest = evalResult[0].value;

		let decrypted = decryptAes(rest, aesK, hmack);
		this.apickli.setGlobalVariable(variableName.toString(), decrypted);
		callback();
	});

	function decryptAes(valorCifrado, aesK, hmack) {
		//console.log("VALOR CIFRADO BEFORE XXX:", valorCifrado);
		const iv_cipherText_hmac = Buffer.from(valorCifrado, 'base64');

		const aesKey = Buffer.from(aesK, "base64");
		const hmacKey = Buffer.from(hmack, 'utf8');
		const macLength = crypto.createHmac('sha256', hmacKey).digest().length;

		const cipherTextLength = iv_cipherText_hmac.length - macLength;
		const iv = iv_cipherText_hmac.slice(0, 16);
		const cipherText = iv_cipherText_hmac.slice(16, cipherTextLength);
		const decipher = crypto.createDecipheriv(getAlgorithm(aesKey), aesKey, iv);

		let decrypted = decipher.update(cipherText);
		decrypted += decipher.final();

		//console.log(decrypted.toString());

		return decrypted.toString();
	}

	Then(/^deciphering AES with accesskey (.*) and hash (.*) the response body path (.*) should be (((?!of type).*))$/, function (accesskey, hmackey, path, value, callback) {
		console.log("INICIA PROCESO DE DESCIFRADO AES EN LA RESPUESTA XXX")

		console.log("LLAVE SIMETRICA A DESCIFRAR ORIGINAL XXX:", accesskey);
		console.log("LLAVE HASH A DESCIFRAR ORIGINAL XXX:", hmackey);

		const aesk = this.apickli.getGlobalVariable(accesskey);
		const hmack = this.apickli.getGlobalVariable(hmackey);
		console.log("SIMETRICO XXX:", aesk);
		console.log("HASH XXX:", hmack);
		const environment = this.apickli.getGlobalVariable('localTest');
		console.log("ENVIROMENT XXX:", environment);
		path = this.apickli.replaceVariables(path);
		var strValue = "";

		const contentType = this.apickli.getResponseObject().body;
		const headers = this.apickli.getResponseObject().headers;
		console.log("CONTENTTYPE XXX:", contentType);
		const contentJson = JSON.parse(contentType);
		console.log("PARSE JSON XXX:", contentJson);

		const evalResult = jsonPath({ resultType: 'all' }, path, contentJson);

		console.log("ENVIRONMENT XXX:", environment);
		if (environment === undefined || environment === false) {
			console.log("INICIA DESCIFRADO AES XXX:");
			console.log("EVALRESULT XXX:", evalResult);
			console.log("EVALRESULT[0] XXX:", evalResult[0]);
			console.log("EVALRESULT[0].value XXX:", evalResult[0].value);
			if (evalResult[0] !== undefined && evalResult[0].value !== undefined) {
				var rest = evalResult[0].value;
				console.log("VALOR A DESCIFRAR XXX:", rest);
				console.log("LLAVE SIMETRICA A DESCIFRAR XXX:", aesk);
				console.log("LLAVE HASH A DESCIFRAR XXX:", hmack);
				strValue = decryptAes(rest, aesk, hmack);
			}
		} else {
			strValue = evalResult[0].value;
		}

		const regExpObject = new RegExp(value);
		const successExp = regExpObject.test(strValue);
		const assertion = getAssertionResultado(successExp, strValue, value, contentType, headers);

		callbackWithAssertion(callback, assertion);
	});

	/**
	 * Funcion para :
	 * descifra los valores de los atributos requeridos del objeto json. 
	 * @param {*} pgpPrivateKey         -> llave privada
	 * @param {*} pgpSecurityKey        -> PGP-Key Password
	 * @param {*} path         			-> path del objeto json donde se encuentra el valor a descifrar
	 * @param {*} value         		-> expresion regular o valor en claro que se espera despues de descifrar
	 */
	Then(/^deciphering PGP with key (.*) using passphrase (.*) the response body path (.*) should be (((?!of type).*))$/, function (pgpPrivateKey, pgpSecurityKey, path, value, callback) {
		const privateKey = this.apickli.getGlobalVariable(pgpPrivateKey);
		const clavePrivada = this.apickli.getGlobalVariable(pgpSecurityKey);
		const environment = this.apickli.getGlobalVariable('localTest');

		if (environment === false || environment === false || environment === undefined) {
			decipherPGP(privateKey, clavePrivada, path, this.apickli, value, callback);
		} else {
			const assertion = this.apickli.assertPathInResponseBodyMatchesExpression(path, value);
			callbackWithAssertion(callback, assertion);
		}
	});

	async function decipherPGP(privateKeyArmored, pgpSecurityKey, path, thApickli, valuePath, callback) {
		const contentType = thApickli.getResponseObject().body;
		const headers = thApickli.getResponseObject().headers;
		const contentJson = JSON.parse(contentType);
		const evalResult = jsonPath({ resultType: 'all' }, path, contentJson);
		var strValue = evalResult[0].value;
		var messageData = "-----BEGIN PGP MESSAGE-----\n\n" + strValue + "\n-----END PGP MESSAGE-----";

		//console.log("reponse privateKey: ", privateKeyArmored);
		console.log("reponse frase: ", pgpSecurityKey);
		console.log("reponse path: ", messageData);
		var valorDecrypted = await (async () => {
			await openpgp.initWorker();
			openpgp.config.ignore_mdc_error = true;
			const { keys: [privateKey] } = await openpgp.key.readArmored(privateKeyArmored);
			await privateKey.decrypt(pgpSecurityKey);

			const { data: decrypted } = await openpgp.decrypt({
				message: await openpgp.message.readArmored(messageData),
				privateKeys: [privateKey]

			});
			return decrypted;
		})();

		console.log("<<valor Descifrado>>: ", valorDecrypted);
		const regExpObject = new RegExp(valuePath);
		const successExp = regExpObject.test(valorDecrypted);
		const assertion = getAssertionResultado(successExp, valorDecrypted, valuePath, contentType, headers);
		setTimeout(function () { callbackWithAssertion(callback, assertion); }, 3000);

	}

	Then(/^I store the deciphering value with PGP private Key as encryption algorithm of body path (.*) as (.*) in global scope$/, function (path, variableName, callback) {
		const privateKey = this.apickli.getGlobalVariable('secretPrivateKey');
		const privatePhrase = this.apickli.getGlobalVariable('secretPassphrase');
		decipherPGPKey(privateKey, privatePhrase, path, this.apickli, variableName, callback);
	});

	async function decipherPGPKey(privateKeyArmored, privatePhrase, path, thApickli, variableName, callback) {
		const contentType = thApickli.getResponseObject().body;
		const headers = thApickli.getResponseObject().headers;
		const contentJson = JSON.parse(contentType);
		const evalResult = jsonPath({ resultType: 'all' }, path, contentJson);
		var strValue = evalResult[0].value;
		var messageData = "-----BEGIN PGP MESSAGE-----\n\n" + strValue.toString() + "\n-----END PGP MESSAGE-----\n";

		try {
			var valorDecrypted = await (async () => {
				await openpgp.initWorker();
				openpgp.config.ignore_mdc_error = true;
				const { keys: [privateKey] } = await openpgp.key.readArmored(privateKeyArmored);
				await privateKey.decrypt(privatePhrase);

				const { data: decrypted } = await openpgp.decrypt({
					message: await openpgp.message.readArmored(messageData),
					privateKeys: [privateKey]
				});
				return decrypted;
			})();

			console.log("<<valor Descifrado>>: ", valorDecrypted);
			thApickli.setGlobalVariable(variableName.toString(), valorDecrypted);
		} catch (err) {
			console.log("ERROR: ", err);
		}
		setTimeout(function () { callback(); }, 900);


	};

	function getAlgorithm(keyBase64) {
		var key = Buffer.from(keyBase64, 'base64');
		switch (key.length) {
			case 16:
				return 'aes-128-cbc';
			case 32:
				return 'aes-256-cbc';
		}
		throw new Error('Invalid key length: ' + key.length);
	}

});
