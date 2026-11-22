# aws-misconfigurations
Batería de pruebas sobre AWS para resolución de vulnerabilidades, optimización de costes y mejoras de rendimiento.
La herramienta ejecuta un conjunto de **reglas** contra una cuenta de AWS y muestra los recursos que incumplen cada una. Cada regla es un fichero YAML, así que añadir una nueva no requiere tocar Python.

## Instalación

```bash
pip install -r requirements.txt
```

Probado con Python 3.12.

## Uso

```bash
# Autenticación mediante perfil o claves de acceso
python aws-misconf.py --profile development
python aws-misconf.py --access_key XXXX --secret_key YYYY

# Solo reglas de riesgo high o superior (high + critical)
python aws-misconf.py --profile development --risk high

# Una regla concreta (repetible: --rule regla-a --rule regla-b)
python aws-misconf.py --profile development --rule ec2-sg-open-ssh

# Otra región (por defecto, la del perfil o us-east-1)
python aws-misconf.py --profile development --region eu-west-1
```

Las reglas con `operation` se ejecutan sobre una única región. Para revisar varias, ejecuta la herramienta una vez por región.
Las reglas con `check` (como las de S3) recorren todas las regiones por sí mismas e ignoran `--region`.

> Evita `--secret_key` en equipos compartidos: la clave queda en el historial de la shell. Usa `--profile` cuando sea posible.

Ejemplo de salida (datos ficticios):

```
Cuenta 123456789012 (arn:aws:iam::123456789012:user/ejemplo) - región us-east-1

✗ [HIGH] ec2-sg-open-ssh - Security Group con SSH abierto a Internet
  GroupId               Name  VPC
  sg-0a1b2c3d4e5f67890  web   vpc-0123456789abcdef0
  1 hallazgo(s)

Resumen: 1 regla(s), 1 hallazgo(s), 0 error(es)
```

## Reglas

Cada regla es un fichero `rules/<id>.yaml`. La regla de ejemplo, [rules/ec2-sg-open-ssh.yaml](rules/ec2-sg-open-ssh.yaml), está comentada y sirve de plantilla.

| Campo | Descripción |
|---|---|
| `id` | Identificador único. Se usa con `--rule`. |
| `name`, `description` | Texto que se muestra en el informe. |
| `risk` | `low`, `mid`, `high` o `critical`. |
| `service` | Nombre del cliente de botocore (`ec2`, `s3`, `rds`...). |
| `operation` | Método del cliente en snake_case (`describe_security_groups`). |
| `params` | Opcional. Con `operation`, parámetros que se pasan a la operación; con `check`, parámetros de la función (p. ej. `threshold`). |
| `query` | Expresión [JMESPath](https://jmespath.org) sobre la respuesta. Debe devolver una lista de recursos vulnerables. |
| `check` | Alternativa a `operation` + `query` para reglas que necesitan varias llamadas (p. ej. una por bucket) o recorrer regiones: nombre de una función registrada en [checks.py](checks.py). |
| `columns` | Columnas de la tabla: nombre de columna → expresión JMESPath aplicada a cada recurso. |

### Reglas incluidas

| Regla | Riesgo | Detecta |
|---|---|---|
| `ec2-sg-open-ssh` | high | Security Groups con SSH abierto a Internet. |
| `s3-bucket-exposed-content` | critical | Buckets cuyo contenido es público: política pública o ACL de lectura pública no anuladas por el Public Access Block del bucket. No se consulta el bloqueo a nivel de cuenta. |
| `s3-bucket-public-acl` | mid | Buckets con una ACL que concede permisos a `AllUsers` o `AuthenticatedUsers`. |
| `ec2-sg-critical-exposed-ports` | critical | Security Groups de todas las regiones habilitadas con puertos críticos (SSH, RDP, bases de datos, Redis, Docker...) abiertos a `0.0.0.0/0` o `::/0`. La lista de puertos se edita en `params.ports` de la regla. |
| `ec2-eip-unassigned` | low | Elastic IPs sin asociar a ningún recurso en todas las regiones habilitadas. Regla de costes, no de seguridad. Se excluyen las IPs BYOIP. |
| `ec2-public-ip-without-lb` | mid | IPs públicas IPv4 (Elastic o efímeras) asignadas directamente a instancias u otras interfaces de red, no a balanceadores ni NAT Gateways. Las exclusiones se editan en `params`. |
| `iam-user-without-mfa` | high | Usuarios IAM con contraseña de consola (cuenta root incluida) y sin MFA activo. Usa el informe de credenciales, que AWS puede reutilizar hasta 4 horas. |
| `iam-credentials-older-than-one-year` | mid | Contraseñas de consola y access keys activas sin cambiar en más de 365 días (cuenta root incluida, solo sus keys). El umbral se edita en `params.max_age_days`. Usa el informe de credenciales. |
| `iam-credentials-expiring-soon` | low | Aviso preventivo: contraseñas que caducan según la política de la cuenta y access keys que cumplen `max_age_days` en menos de `warning_days` (15) días. Mantén `max_age_days` igual que en `iam-credentials-older-than-one-year`. |
| `iam-user-excess-admin-roles` | mid | Usuarios IAM con más de 3 asignaciones administrativas (políticas directas, por grupo o roles que pueden asumir). Umbral y políticas de AWS consideradas administrativas configurables en `params`. |

Las reglas de S3 necesitan los permisos `s3:ListAllMyBuckets`, `s3:GetBucketAcl`, `s3:GetBucketPolicyStatus` y `s3:GetBucketPublicAccessBlock`. Si falta alguno para un bucket, la regla falla indicando cuál.
La regla de IAM necesita `iam:GetAccountAuthorizationDetails`.
Las reglas de usuarios sin MFA y de credenciales (antiguas y a punto de caducar) necesitan `iam:GenerateCredentialReport` e `iam:GetCredentialReport`.
La regla de puertos críticos necesita `ec2:DescribeRegions` y `ec2:DescribeSecurityGroups`. Se solapa con `ec2-sg-open-ssh` en el puerto 22.
La regla de Elastic IPs necesita `ec2:DescribeRegions` y `ec2:DescribeAddresses`.
La regla de IPs públicas sin balanceador necesita `ec2:DescribeRegions` y `ec2:DescribeNetworkInterfaces`.

## Cómo añadir una regla

1. Busca la operación en la [documentación de boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/) y escribe el nombre del método en snake_case.
2. Copia `rules/ec2-sg-open-ssh.yaml` a `rules/<tu-id>.yaml` y rellena los campos.
3. Prueba la `query` con una respuesta real de la operación en el [probador de JMESPath](https://jmespath.org/).
4. Ejecuta los tests:
   ```bash
   pip install pytest
   python -m pytest
   ```
   Validan que la regla carga, que tiene un riesgo válido, que la sintaxis JMESPath es correcta y que la operación existe en botocore.
5. Ejecuta tu regla contra una cuenta de prueba:
   ```bash
   python aws-misconf.py --profile development --rule <tu-id>
   ```

Si la lógica de tu regla no es trivial, añade un test con `botocore.stub.Stubber`, como en [tests/test_rules.py](tests/test_rules.py).

## Estructura

```
aws-misconf.py   CLI (click) y autenticación (botocore)
engine.py        carga, filtrado y ejecución de reglas
checks.py        chequeos en Python para reglas con `check`
rules/           una regla por fichero YAML
tests/           tests de reglas y del motor
```

