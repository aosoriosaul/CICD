Feature: /aclaraciones/busquedas/estatus/ POST
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
        When  I GET `apigeeDomain`/operaciones-baz/seguridad/v1/aplicaciones/llaves
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

    Scenario Outline: /estatus/busquedas 200 ok
        Given I set bearer token
        And I set Content-Type header to application/json
        And I have valid client TLS configuration
        And I set x-ismock header to true
        And I set x-id-acceso header to `idAccess`
        And I set x-ip-origen header to <ipOrigen>
        And I set body to <body>
        When I POST to `apigeeDomain`/operaciones-baz/plataforma-aclaraciones/administracion-aclaraciones/`deploymentSuffix`/aclaraciones/busquedas/estatus
        Then response code should be 200
        And response body should be valid json
        And response body path $.mensaje should be ^Operaci(o|ó)n (e|E)xitosa(.|)$
        And response body path $.folio should be ^[a-zA-Z0-9,-]+$
        And response body path $.resultado.aclaraciones.folio should be ^[\w\-\s\,\./a-zA-Z0-9_/:]+$
        And deciphering with the key privateKey the response field $.resultado.aclaraciones.numeroCuenta and RSA_PKCS1_PADDING as encryption algorithm should be ^[a-z]
        And deciphering with the key privateKey the response field $.resultado.aclaraciones.numeroTarjeta and RSA_PKCS1_PADDING as encryption algorithm should be [a-zA-Z]
        And response body path $.resultado.aclaraciones.motivo should be ^[\w\-\s\,\./a-zA-Z0-9_/:]+$
        And deciphering with the key privateKey the response field $.resultado.aclaraciones.montoTotal and RSA_PKCS1_PADDING as encryption algorithm should be ^[\w\-\s\,\./a-zA-Z0-9_/:]+$
        And response body path $.resultado.aclaraciones.producto should be ^[\w\-\s\,\./a-zA-Z0-9_/:]+$
        And response body path $.resultado.aclaraciones.concepto should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$
        And response body path $.resultado.aclaraciones.clasificacion should be [a-zA-Z]
        And response body path $.resultado.aclaraciones.dictamen should be [a-zA-Z]
        And response body path $.resultado.aclaraciones.fechaCreacion should be [a-zA-Z]
        And response body path $.resultado.aclaraciones.fechaResolucion should be [a-zA-Z]
        And response body path $.resultado.aclaraciones.estatus should be [a-zA-Z]

    Examples:
        | body                                                             |
        | {"idEstatus":1,"fechaInicio":"10/09/2021","fechaFin":"25/09/2021"} |


    Scenario Outline:  /estatus/busquedas 400 bad request.

        Given I set bearer token
        And I set Content-Type header to application/json
        And I have valid client TLS configuration
        And I set x-ismock header to true
        And I set x-id-acceso header to `idAccess`
        And I set x-ip-origen header to <ipOrigen>
        And I set body to <body>
        And I have valid client TLS configuration

        When I POST to `apigeeDomain`/operaciones-baz/plataforma-aclaraciones/administracion-aclaraciones/`deploymentSuffix`/aclaraciones/busquedas/estatus
        Then response code should be 400
        And response body should be valid json

        And response body path $.codigo should be ^400.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{4}$
        And response body path $.mensaje should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$
        And response body path $.folio should be [a-zA-Z0-9\W]{1,}
        And response body path $.info should be ^https:\/\/baz-developer\.bancoazteca\.com\.mx\/\w{4,6}#400\.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{0,}|[A-Z]{0,}\d{0,}$
        And response body path $.detalles[*] should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$

    Examples:
        | body                                                             |
        | {"idEstatus":0,"fechaInicio":"10/09/2021","fechaFin":"25/09/2021"} |

    Scenario Outline:  /estatus/busquedas 401 bad request.

        Given I set bearer token
        And I set Content-Type header to application/json
        And I have valid client TLS configuration
        And I set x-ismock header to true
        And I set x-id-acceso header to `idAccess`
        And I set x-ip-origen header to <ipOrigen>
        And I set body to <body>
        #And I have valid client TLS configuration

        When I POST to `apigeeDomain`/operaciones-baz/plataforma-aclaraciones/administracion-aclaraciones/`deploymentSuffix`/aclaraciones/busquedas/estatus
        Then response code should be 401
        And response body should be valid json

        And response body path $.codigo should be ^401.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{4}$
        And response body path $.mensaje should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$
        And response body path $.folio should be [a-zA-Z0-9\W]{1,}
        And response body path $.info should be ^https:\/\/baz-developer\.bancoazteca\.com\.mx\/\w{4,6}#401\.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{0,}|[A-Z]{0,}\d{0,}$
        And response body path $.detalles[*] should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$

    Examples:
        | body                                                                 |
        | {"idEstatus":"bad","fechaInicio":"10/09/2021","fechaFin":"25/09/2021"} |

    Scenario Outline:  /estatus/busquedas 404 not found.

        Given I set bearer token
        And I set Content-Type header to application/json
        And I have valid client TLS configuration
        And I set x-ismock header to true
        And I set x-id-acceso header to `idAccess`
        And I set x-ip-origen header to <ipOrigen>
        And I set body to <body>

        When I POST to `apigeeDomain`/operaciones-baz/plataforma-aclaraciones/administracion-aclaraciones/`deploymentSuffix`/aclaraciones/busquedas/estatus
        Then response code should be 404
        And response body should be valid json

        And response body path $.codigo should be ^404.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{4}$
        And response body path $.mensaje should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$
        And response body path $.folio should be [a-zA-Z0-9\W]{1,}
        And response body path $.info should be ^https:\/\/baz-developer\.bancoazteca\.com\.mx\/\w{4,6}#404\.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{0,}|[A-Z]{0,}\d{0,}$
        And response body path $.detalles[*] should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$

    Examples:
        | body                                                                |
        | {"idEstatus":"nf","fechaInicio":"10/09/2021","fechaFin":"25/09/2021"} |

    Scenario Outline:  /estatus/busquedas 500 internal server error.

        Given I set bearer token
        And I set Content-Type header to application/json
        And I have valid client TLS configuration
        And I set x-ismock header to true
        And I set x-id-acceso header to `idAccess`
        And I set x-ip-origen header to <ipOrigen>
        And I set body to <body>

        When I POST to `apigeeDomain`/operaciones-baz/plataforma-aclaraciones/administracion-aclaraciones/`deploymentSuffix`/aclaraciones/busquedas/estatus

        Then response code should be 500
        And response body should be valid json

        And response body path $.codigo should be ^500.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{4}$
        And response body path $.mensaje should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$
        And response body path $.folio should be [a-zA-Z0-9\W]{1,}
        And response body path $.info should be ^https:\/\/baz-developer\.bancoazteca\.com\.mx\/\w{4,6}#500\.Operaciones-Baz-Plataforma-Aclaraciones-Gestion-Aclaraciones.\d{0,}|[A-Z]{0,}\d{0,}$
        And response body path $.detalles[*] should be ^[A-Za-záéíóúÁÉÍÓÚ0-9.,-\s:]{1,255}$

    Examples:
        | body                                                                |
        | {"idEstatus":null,"fechaInicio":"10/09/2021","fechaFin":"25/09/2021"} |