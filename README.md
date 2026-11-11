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
# Ejecutar todas las reglas con un perfil de ~/.aws/credentials
python aws-misconf.py --profile development

# Credenciales explícitas
python aws-misconf.py --access_key XXXX --secret_key YYYY

# Solo reglas de riesgo high o superior (high + critical)
python aws-misconf.py --profile development --risk high

# Una regla concreta (repetible: --rule regla-a --rule regla-b)
python aws-misconf.py --profile development --rule ec2-sg-open-ssh

# Otra región (por defecto, la del perfil o us-east-1)
python aws-misconf.py --profile development --region eu-west-1
```

Las reglas se ejecutan sobre una única región. Para revisar varias, ejecuta la herramienta una vez por región.

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
| `params` | Opcional. Parámetros que se pasan a la operación. |
| `query` | Expresión [JMESPath](https://jmespath.org) sobre la respuesta. Debe devolver una lista de recursos vulnerables. |
| `columns` | Columnas de la tabla: nombre de columna → expresión JMESPath aplicada a cada recurso. |

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
rules/           una regla por fichero YAML
tests/           tests de reglas y del motor
```
