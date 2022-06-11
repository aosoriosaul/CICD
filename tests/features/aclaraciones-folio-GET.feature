Feature: /aclaraciones/{folio} GET
    Obtener Informacion de Aclaraciones de cargos no reconocidos

    Scenario: Negocio un consumer key y secret key de la app de prueba
        Given I have basic authentication credentials `apigeeUsername` and `apigeePassword`
        And I have valid client TLS configuration
        When I GET `apigeeHost`/v1/organizations/`apigeeOrg`/developers/`apigeeDeveloper`/apps/`apigeeApp`
        Then response code should be 200
        And response body should be valid json
        And I store the value of body path $.credentials[0].consumerKey as globalConsumerKey in global scope
        And I store the value of body path $.credentials[0].consumerSecret as globalConsumerSecret in global scope

    Scenario: Negocia un access token con el Authorization server

        Given I set form parameters to
        | parameter  | value              |
        | grant_type | client_credentials |

        And I have basic authentication credentials `globalConsumerKey` and `globalConsumerSecret`
        And I have valid client TLS configuration
        When I POST to `apigeeDomain`/`apigeeOauthEndpoint`

        Then response code should be 200
        And response body should be valid json
        And I store the value of body path $.access_token as access token


    Scenario: Obtencion de llaves asimétricas
        Given I set bearer token
        And I have valid client TLS configuration
        And I set x-ismock header to true
        When I GET `apigeeDomain`/operaciones-baz/seguridad/v1/aplicaciones/llaves
        Then response code should be 200
        And response body should be valid json
        And response body path $.mensaje should be ^([A-Za-zá-úÁ-Ú0-9\s,.-])+$
        And response body path $.folio should be ^[a-z0-9-]{1,}$
        And response body path $.resultado.idAcceso should be ^[a-zA-Z0-9]{1,60}$
        And I store the value of body path $.resultado.idAcceso as idAccess in global scope
        And I store the deciphering value encrypted with AES of body path $.resultado.accesoPublico as publicKey in global scope
        And I store the deciphering value encrypted with AES of body path $.resultado.accesoPrivado as privateKey in global scope
        And I store the deciphering value encrypted with AES of body path $.resultado.accesoSimetrico as accessSymmetric in global scope
        And I store the deciphering value encrypted with AES of body path $.resultado.codigoAutentificacionHash as codeHash in global scope

    Scenario Outline: /aclaraciones/{folio} 200 ok
        Given I set bearer token
        And I set Content-Type header to application/json
        And I have valid client TLS configuration
        And I set x-ismock header to true
        And I set x-id-acceso header to `idAccess`
        And I set x-ip-origen header to <ipOrigen>
        
        When I GET `apigeeDomain`/operaciones-baz/plataforma-aclaraciones/administracion-aclaraciones/`deploymentSuffix`/aclaraciones/<folio>

        Then response code should be 200
        And response body should be valid json

        And response body path $.mensaje should be ^Operaci(o|ó)n (e|E)xitosa(.|)$
        And response body path $.folio should be ^[a-zA-Z0-9,-]+$
        And response body path $.resultado.folio should be ^[0-9a-zA-Z,-]+$
        And response body path $.resultado.motivo should be ^[a-zA-Z ]+$
        And deciphering with the key privateKey the response field $.resultado.montoReclamado and RSA_PKCS1_PADDING as encryption algorithm should be ^.{0,1000}$
        # And deciphering with the key privateKey the response field $.resultado.montoReclamado and RSA_PKCS1_PADDING as encryption algorithm should be ^[0-9.,]+
        And deciphering with the key privateKey the response field $.resultado.comision and RSA_PKCS1_PADDING as encryption algorithm should be ^.{0,1000}$
        And response body path $.resultado.producto should be ^[a-zA-Z /-]+$
        And response body path $.resultado.tipoAclaracion should be ^[a-zA-Z ]+$
        And response body path $.resultado.tipificacion should be ^[a-zA-Z ]+$
        And response body path $.resultado.idSucursal should be ^[0-9]+
        And response body path $.resultado.nombreSucursal should be ^[a-zA-Z ]+$
        And response body path $.resultado.comentario should be ^[a-zA-Z ]+$
        And response body path $.resultado.estatus should be ^[a-zA-Z ]+$
        And response body path $.resultado.tiempoResolucion should be ^[0-9]+
        And response body path $.resultado.fechaPromesa should be ^[a-zA-Z0-9/]+
        And response body path $.resultado.fechaCreacion should be ^[a-zA-Z0-9/]+
        And response body path $.resultado.fechaResolucion should be ^[a-zA-Z0-9/]+
        And response body path $.resultado.horaCreacion  should be ^[\w\-\s\,\./a-zA-Z0-9_/:]+$
        And response body path $.resultado.comentarioResponsable should be ^[a-zA-Z ]+$
        And response body path $.resultado.movimientos[*].tipoOperacion should be ^[a-zA-Z -]+$
        And deciphering with the key privateKey the response field $.resultado.movimientos[*].monto and RSA_PKCS1_PADDING as encryption algorithm should be ^.{0,1000}$
        And response body path $.resultado.movimientos[*].descripcionComercio should be ^[a-zA-Z ,.]+$
        And response body path $.resultado.movimientos[*].canalOperacion should be ^[0-9]+$
        And response body path $.resultado.movimientos[*].fechaImporte should be ^[a-zA-Z0-9/]+
        And response body path $.resultado.movimientos[*].fallo should be ^[a-zA-Z ,.]+$
        And response body path $.resultado.Operador.accion should be ^[a-zA-Z ]+$
        And response body path $.resultado.Operador.nombre should be ^[a-zA-Z ]+$
        And response body path $.resultado.documentos[*].idTipo should be ^[0-9]+
        And response body path $.resultado.documentos[*].uri should be ^[0-9-]+$
        And deciphering with the key privateKey the response field $.resultado.cliente.id and RSA_PKCS1_PADDING as encryption algorithm should be ^.{0,1000}$
        And deciphering with the key privateKey the response field $.resultado.cliente.numeroCuenta and RSA_PKCS1_PADDING as encryption algorithm should be ^.{0,1000}$
        And deciphering with the key privateKey the response field $.resultado.cliente.numeroTarjeta and RSA_PKCS1_PADDING as encryption algorithm should be ^.{0,1000}$
        And response body path $.resultado.cliente.estatusTarjeta should be [a-zA-Z]

    Examples:
        | folio                  |
        | 098-201908131017594500 |

    Scenario Outline: /aclaraciones/{folio} 400 bad request.

        Given I set Content-Type header to application/json
        And I set bearer token
        And I set x-ismock header to true
        And I set x-id-acceso header to `idAccess`
        And I set x-ip-origen header to <ipOrigen>
        And I have valid client TLS configuration
        #And I set body to <folio>
        When I GET `apigeeDomain`/operaciones-baz/plataforma-aclaraciones/administracion-aclaraciones/`deploymentSuffix`/aclaraciones/<folio>
        Then response code should be 400
        And response body should be valid json
        And response body path $.codigo should be ^400.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{4}$
        And response body path $.mensaje should be ^[A-Z0-9a-zñÑáéíóúÁÉÍÓÚ _.:,\-]*$
        And response body path $.folio should be ^[A-Z0-9a-zñÑáéíóúÁÉÍÓÚ _.:,\-]*$
        And response body path $.info should be ^https:\/\/baz-developer\.bancoazteca\.com\.mx\/\w{4,6}#400.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{0,}|[A-Z]{0,}\d{0,}$
        And response body path $.detalles[*] should be ^[A-Z0-9a-zñÑáéíóúÁÉÍÓÚ _.:,\-]*$

    Examples:
         | folio |
         | ABC   |

    Scenario Outline: /aclaraciones/{folio} 401 bad request.

        Given I set Content-Type header to application/json
        And I set bearer token
        And I set x-ismock header to true
        And I set x-id-acceso header to `idAccess`
        And I set x-ip-origen header to <ipOrigen>
        And I have valid client TLS configuration
        #And I set body to <folio>
        When I GET `apigeeDomain`/operaciones-baz/plataforma-aclaraciones/administracion-aclaraciones/`deploymentSuffix`/aclaraciones/<folio>
        Then response code should be 401
        And response body should be valid json
        And response body path $.codigo should be ^401.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{4}$
        And response body path $.mensaje should be ^[A-Z0-9a-zñÑáéíóúÁÉÍÓÚ _.:,\-]*$
        And response body path $.folio should be ^[A-Z0-9a-zñÑáéíóúÁÉÍÓÚ _.:,\-]*$
        And response body path $.info should be ^https:\/\/baz-developer\.bancoazteca\.com\.mx\/\w{4,6}#401.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{0,}|[A-Z]{0,}\d{0,}$
        And response body path $.detalles[*] should be ^[A-Z0-9a-zñÑáéíóúÁÉÍÓÚ _.:,\-]*$

    Examples:
         | folio |
         | nf   |

    Scenario Outline: /aclaraciones/{folio} 404 bad request.

        Given I set Content-Type header to application/json
        And I set bearer token
        And I set x-ismock header to true
        And I set x-id-acceso header to `idAccess`
        And I set x-ip-origen header to <ipOrigen>
        And I have valid client TLS configuration
        #And I set body to <folio>
        When I GET `apigeeDomain`/operaciones-baz/plataforma-aclaraciones/administracion-aclaraciones/`deploymentSuffix`/aclaraciones/<folio>
        Then response code should be 404
        And response body should be valid json
        And response body path $.codigo should be ^404.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{4}$
        And response body path $.mensaje should be ^[A-Z0-9a-zñÑáéíóúÁÉÍÓÚ _.:,\-]*$
        And response body path $.folio should be ^[A-Z0-9a-zñÑáéíóúÁÉÍÓÚ _.:,\-]*$
        And response body path $.info should be ^https:\/\/baz-developer\.bancoazteca\.com\.mx\/\w{4,6}#404.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{0,}|[A-Z]{0,}\d{0,}$
        And response body path $.detalles[*] should be ^[A-Z0-9a-zñÑáéíóúÁÉÍÓÚ _.:,\-]*$

    Examples:
         | folio |
         | bad   |

    Scenario Outline: /aclaraciones/{folio} 500 bad request.

        Given I set Content-Type header to application/json
        And I set bearer token
        And I set x-ismock header to true
        And I set x-id-acceso header to `idAccess`
        And I set x-ip-origen header to <ipOrigen>
        And I have valid client TLS configuration
        #And I set body to <folio>
        When I GET `apigeeDomain`/operaciones-baz/plataforma-aclaraciones/administracion-aclaraciones/`deploymentSuffix`/aclaraciones/<folio>
        Then response code should be 500
        And response body should be valid json
        And response body path $.codigo should be ^500.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{4}$
        And response body path $.mensaje should be ^[A-Z0-9a-zñÑáéíóúÁÉÍÓÚ _.:,\-]*$
        And response body path $.folio should be ^[A-Z0-9a-zñÑáéíóúÁÉÍÓÚ _.:,\-]*$
        And response body path $.info should be ^https:\/\/baz-developer\.bancoazteca\.com\.mx\/\w{4,6}#500.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{0,}|[A-Z]{0,}\d{0,}$
        And response body path $.detalles[*] should be ^[A-Z0-9a-zñÑáéíóúÁÉÍÓÚ _.:,\-]*$

    Examples:
         |folio|
         | null|