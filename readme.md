# RGHA

RGHA o random generic Hash algorithm es una variante del algoritmo SHA-256 cuyos derechos están atados al **departamento de comercio de estados unidos** cuyo paper fue publicado el 08/2015 el cual se puede encontrar en el siguiente link: http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf.

**Advertencia**: Este algoritmo no esta validado, es solo investigación cualquier falla de seguridad no es responsabilidad mia.

## Estado del proyecto y proyecciones

El proyecto de RGHA actualmente está en fase de desarrollo, las proyecciones es tener una librería de Python, Kotlin, Java Rust, Golang y otros lenguajes de programación por ahora es solo una prueba de concepto.

## Caracteristicas de RGHA

RGHA es un algoritmo que entrega siempre un valor hexadecimal de 256 Bits o 64 caracteres en formato hexadecimal, este formato de 64 caracteres siempre será constante aunque la cadena que le pasamos al algoritmo sea una cadena de un carácter, sólo los tipos de datos `string` son compatibles como entrada para generar un hash, lo que significa que si quieres pasar un numero deberás primero codificarlo como una cadena de los contrario te lanzara un error, la idea central del algoritmo es calcular los hashes con una versión modificada del algoritmo SHA256, por lo que tiene sus características:

- Resistencia a colisiones.
- Cambios en avalancha.
- Es fácil de armar pero difícil de desarmar.

A continuación se detalla el funcionamiento paso a paso.

## Funciones y convenciones

w: Words

H: Hash inciales

K: Constantes del SHA256

Las funciones utilizadas están tomadas directamente del paper de Secure Hash Algorithm y las convenciones usadas en este documento de explicación son idénticas y son las siguientes

| Operación  | Nombre                 |
| ---------- | ---------------------- |
| ^          | Y lógico               |
| ∨          | O logico               |
| ⊕          | XOR                    |
| ¬          | No logico              |
| +          | Suma modulo 2 \*\* 32  |
| ROTR       | Rotar a la derecha     |
| SHR        | Desplazar a la derecha |
| CH(x y z)  | Elegir                 |
| MAJ(x y z) | Mayoría                |
| Σ0(x)      | Sum Cero               |
| Σ1(x)      | Sum Uno                |
| σ0(x)      | Sigma Cero             |
| σ1(x)      | Sigma Uno              |

### Operaciones de Bits

Las **operaciones de bits** son un conjunto de operaciones lógicas que se aplican bit a bit, funcionan como las operaciones lógicas del lenguaje de programación que estamos ocupando, pero repitiendo lo anterior se aplican bit a bit

**Y lógico**
El **Y lógico** es un Y booleano que se aplica en todos los bits (0 y 1) de nuestras estructuras de datos, entonces las tablas booleanas se pueden aplicar de igual manera a esta operación solo que podemos evaluar varios números a la vez como se puede apreciar en la siguiente tabla

| nombre   | b1  | b2  | b3  | b4  | b5  |
| -------- | --- | --- | --- | --- | --- |
| Numero 1 | 1   | 1   | 0   | 1   | 0   |
| Numero 2 | 0   | 0   | 1   | 1   | 0   |
| ^        | 0   | 0   | 0   | 1   | 0   |

también se le suele encontrar con el nombre de conjunción.

**Ó logico**

El **O logico** es el mismo concepto de ó booleano aplicado a los bits
| nombre | b1 | b2 | b3 | b4 | b5 |
| -------- | --- | --- | --- | --- | --- |
| Numero 1 | 1 | 1 | 0 | 1 | 0 |
| Numero 2 | 0 | 0 | 1 | 1 | 0 |
| ∨ | 1 | 1 | 1 | 1 | 0 |

también se le suele encontrar con el nombre de disyunción.

**XOR**
La operación XOR o "ó exclusivo" es un operador que funciona como un ó pero excluye los bits para cuando los dos son "1", es decir vamos a interpolar todos los bits de una cadena menos donde ambos bits sean "1"

| nombre   | b1  | b2  | b3  | b4  | b5  |
| -------- | --- | --- | --- | --- | --- |
| Numero 1 | 1   | 1   | 0   | 1   | 0   |
| Numero 2 | 0   | 0   | 1   | 1   | 0   |
| ∨        | 1   | 1   | 1   | 0   | 0   |

**No Logico**

El no lógico es la inversión de los valores de Bits es decir que todos los bits toman un valor contrario al que tenían es igual a la negación booleana pero se puede aplicar a múltiples bits a la vez

| nombre   | b1  | b2  | b3  | b4  | b5  |
| -------- | --- | --- | --- | --- | --- |
| Numero 1 | 1   | 1   | 0   | 1   | 0   |
| ¬        | 0   | 0   | 1   | 0   | 1   |

**Suma modulo 32**

La suma módulo 32 es una operación importante dentro del algoritmo porque mantiene la consistencia de cada hash final a 32 bits si no respetamos la forma de la suma módulo 32 el hash final no va a respetar los 256 bits.

La fórmula para la suma en módulo 32 tiene la siguiente forma:

![formula para la suma modulo 32](./images/m32.png)

**SHR**

El desplazamiento a la derecha desplaza un bit hacia la derecha `n` veces, si no hay más bits disponibles el valor se descarta.

| nombre   | b1  | b2  | b3  | b4  | b5  |
| -------- | --- | --- | --- | --- | --- |
| Numero 1 | 1   | 1   | 0   | 0   | 0   |
| SHR 2    | 0   | 0   | 1   | 1   | 0   |

**ROTR**

El similar al desplazamiento de bits con la diferencia es que si el valor llega al máximo el valor se rota hacia la primera posición

| nombre   | b1  | b2  | b3  | b4  | b5  |
| -------- | --- | --- | --- | --- | --- |
| Numero 1 | 0   | 0   | 0   | 1   | 1   |
| ROTR 1   | 1   | 0   | 0   | 0   | 1   |
| ROTR 2   | 1   | 1   | 0   | 0   | 0   |

### Funciónes

**CH**

La función Choose solo usa el bit `x` para escoger un bit (y o z) si el bit `x=1` se escoge `y`, si `x=0` se escoge `z`

| nombre     | b1  | b2  | b3  | b4  | b5  |
| ---------- | --- | --- | --- | --- | --- |
| x          | 0   | 0   | 0   | 1   | 1   |
| y          | 1   | 0   | 0   | 0   | 1   |
| z          | 1   | 1   | 0   | 0   | 0   |
| CH (x y z) | 1   | 1   | 0   | 0   | 1   |

La función se define por la fórmula:
![formula para la función Choose](./images/ch.png)

**MAJ**

La función Majority retorna la mayoria de 3 bits si dos o tres bits tienen el valor 1 se escoge el valor 1 si solo un bit tiene un valor de 1 se escoge el valor 0

| nombre      | b1  | b2  | b3  | b4  | b5  |
| ----------- | --- | --- | --- | --- | --- |
| x           | 0   | 0   | 0   | 1   | 1   |
| y           | 1   | 0   | 0   | 0   | 1   |
| z           | 1   | 1   | 0   | 0   | 0   |
| MAJ (x y z) | 1   | 0   | 0   | 0   | 1   |

![fórmula para la función MAJ](./images/maj.png)

**SUM cero, SUM uno, Sigma cero y Sigma uno**

Las operaciones anteriores se combinan para dar paso a estas operaciones el símbolo escogido no tiene relación con la operación de suma.

![fórmula para la función SUM0 y SUM1](./images/sum2.png)

![fórmula para la función Sigma0 y Sigma1](./images/sigmas.png)

### Constantes

Las constantes utilizadas son iguales a las del estándar SHA256 que están definidas al principio del código y son las siguientes

las constantes K0 a K63 son:

```plain
    0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5 0x3956c25b 0x59f111f1 0x923f82a4 0xab1c5ed5
    0xd807aa98 0x12835b01 0x243185be 0x550c7dc3 0x72be5d74 0x80deb1fe 0x9bdc06a7 0xc19bf174
    0xe49b69c1 0xefbe4786 0x0fc19dc6 0x240ca1cc 0x2de92c6f 0x4a7484aa 0x5cb0a9dc 0x76f988da
    0x983e5152 0xa831c66d 0xb00327c8 0xbf597fc7 0xc6e00bf3 0xd5a79147 0x06ca6351 0x14292967
    0x27b70a85 0x2e1b2138 0x4d2c6dfc 0x53380d13 0x650a7354 0x766a0abb 0x81c2c92e 0x92722c85
    0xa2bfe8a1 0xa81a664b 0xc24b8b70 0xc76c51a3 0xd192e819 0xd6990624 0xf40e3585 0x106aa070
    0x19a4c116 0x1e376c08 0x2748774c 0x34b0bcb5 0x391c0cb3 0x4ed8aa4a 0x5b9cca4f 0x682e6ff3
    0x748f82ee 0x78a5636f 0x84c87814 0x8cc70208 0x90befffa 0xa4506ceb 0xbef9a3f7 0xc67178f2
```

Las constantes H0 a H7 son:

```plain
    0x6A09E667
    0xBB67AE85
    0x3C6EF372
    0xA54FF53A
    0x510E527F
    0x9B05688C
    0x1F83D9AB
    0x5BE0CD19
```

Las constantes LT son

```plain
97 98 99 100 101 102 103 104 105 106
107 108 109 110 111 112 113 114 115
116 117 118 119 120 121 65 66 67 68
69  70  71  72  73  74  75 76 77 78
79  80  81  82  83  84  85 86 87 88 89
```

La constante R es `0x13D573`

## Algoritmo

Ahora que tenemos los bloques principales vamos a hablar del algoritmo, este se divide en 4 pasos, el paso 1 es el preprocesamiento de la cadena, el paso 2 es la mutación de los hashes, el paso 3 la randomización del hash y el paso 4 es concatenar y generar el hash. Ahora pasaremos a revisar cada uno de esos pasos

### Preprocesamiento

El primer paso es el preprocesamiento y asegura que nuestras cadenas sean múltiplos de 512 **esto es importante** y el procedimiento es el siguiente

Paso 1: Pasar nuestra cadena a números binarios y guardar el tamaño de la cadena que le denominaremos `l`

Paso 2: Agregar un bit extra al final **obligatorio** que siempre es 1

Paso 3: Calcular la cantidad de ceros para agregar al final, este calculo se da por la formula `(448 - 1 - l) % 512`

Paso 4: Poner la cantidad de ceros resultantes al final de la cadena codificada

Paso 5: Codificar el tamaño de la cadena `l` como número binario **ojo** no desde la cadena sino el número.

Paso 6: Formatear la cadena en un formato de 64 bits (anteponiendo ceros) y se agrega al final de la cadena de bits

Si todos los pasos son correctos deberías tener como resultado una cadena con un largo múltiple de 512 lo cual es importante para el siguiente paso

### Mutación de Hashes

En este paso es el corazón del metodo SHA256 en este paso vamos a mutar los hashes, para generar el hash final, este proceso consta de varios pasos importantes, que se describen como

Paso 1: Dividir en chunks de 512 bits nuestra cadena, por eso es importante que la cadena sea siempre divisible por 512 bits porque la vamos a dividir en trozos de exactamente 512 bits.

Paso 2: Inicializar nuestras variables para contener los valores de los hashes iniciales, los hashes iniciales son las constantes `H` que detallamos arriba y las guardaremos en las variables `a, b, c, d, e, f g y h` los cuales se denominan registros y estas variables debemos definirlas fuera del bucle que vamos a detallar más adelante

Paso 3: Iterando cada uno de los trozos vamos a hacer todos estos pasos de forma iterativa.

Paso 4: Inicializamos nuestras palabras o vector `w` con 64 ceros

Paso 5: Cortamos nuestro chunk de 512 bits en trozos de 32 bits los cuales nos darán 16 partes

Paso 6: En el vector `w` vamos a copiar nuestros 16 trozos de 32 bits en los primeros 16 registros de nuestras palabras desde `w_1 a w_16` los demás registros deben quedar a cero

Paso 7: Calculamos los registros restantes, desde las palabras 17 a 64 `w_16 a w_64` vamos a aplicar la siguiente operación:

`w_n = σ1(w[n-2]) + w[n-7] + σ0(w[n-15]) + w[n-16]`

Paso 8: Iteramos sobre W_0 a W_63

Paso 7: Calculamos los valores temporales T0 y T1 que son registros que se usan para actualizar los hashes, para calcular los valores están dadas las siguientes formulas:

`T0 = h + Σ1(e) + Ch(e, f, g) + k_1 + w_i`

`T1 = Σ0(a) + Maj(a, b, c)`

Y actualizamos los registros de acuerdo a esta regla:
| Registro | Valor |
| --- | --- |
| h | g |
| g | f |
| f | e |
| e | d + T1 |
| d | c |
| c | b |
|b|a|
| a | T1 + T2 |

Paso 9: Mutamos los valores H siguiendo la regla:

| Registro | Valor |
| -------- | ----- |
| H_0      | a     |
| H_1      | b     |
| H_2      | c     |
| H_3      | d     |
| H_4      | e     |
| H_5      | f     |
| H_6      | g     |
| H_7      | h     |

Paso 10: Repetir el proceso para la siguiente pieza de 512 bits y si no quedas tenemos el hash final

### Randomización

Este proceso es la gran diferencia con el algoritmo original ya que se hace un paso extra que no está presente en SHA256 aunque el algoritmo anterior ya tiene diferencias con el original, pero aqui viene la modificación más grande y se describe por los siguientes pasos

Paso 1: Se toma el vector H previamente calculado y se hace una copia

Paso 2: Con el algoritmo de números aleatorios Mersenne Twister iteramos cada uno de los hashes en el vector H y hacemos lo siguiente

Paso 3: Ponemos como semilla el valor `H[n]`

Paso 4: Calculamos un valor entre 0 y la constante R que se explicó más arriba

Paso 5: Hacemos módulo 50 y tomamos un carácter de la tabla LT (son valores ASCII) los convertimos en cadena y calculamos los vectores `H[n]` de cada uno a los cuales los llamaremos valores `Hc`

Paso 6: Sumamos los valores de nuestros vector Hc con los valores de nuestro vector H

`H[n] = Hc[n] + Hn`

Paso 7: Sacamos módulo 64 a cada uno de nuestros valores `i = H[n]` y los usamos para tomar constantes del vector K y sumarlas a H

`H[n] = k[i] + H[n]`

Y ya tenemos todos nuestros valores ahora vamos a obtener el Hash

### Generar el Hash

Para generar el Hash se toman cada uno de nuestros valores H y se concatenan como cadena y se pasan a hexadecimal

```
Concatenamos:
H0 + H1 + H2 + H3 + H4 + H5 + H6
```

Y al final para la cadena "Hello, World" el resultado es el siguiente:

```
755b5f4ae80b715f88434ccfbd23870e58ce16747d3215192e882065f4bcd805
```
