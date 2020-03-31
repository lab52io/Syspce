![](Images/Syspce2.PNG)
# *Sysmon Processes Correlation Engine*

"Sysmon Processes Correlation Engine" (Syspce) es un complemento de la herramienta 
de monitorización de entornos Windows Sysmon, capaz de añadir una capa de 
correlación a los eventos que esta genera. Tiene como objetivo poder detetar 
actividades maliciosas, relacionando entre si las acciones atómicas identificadas 
por Sysmon.

Por una parte, permite relacionar acciones que sucenden en la jerarquía de 
ejecución de los procesos, es decir, un proceso siempre cumple un relación de 
parentesco padre->hijo con su creador, por lo que se puede componer de forma 
general el "arbol genealógico" de los procesos de un sistema. Esto es muy útil
para detectar las acciones del malware mediante una estrategía de comportamiento
y no de firmas. Sysmon en su ID 1 establece una relación de parentesco mínima 
padre/hijo, pero el correlador es capaz de trabajar en la detección de todo 
el arbol, relacionando acciones que han realizado los procesos sin importar la 
profundidad en la jerarquia.

En segundo lugar, presenta capacidades de modelar la actividad normal de los 
procesos mediante la definición de lineas base y alertar cuando un proceso no
se comporta como normalmente lo hace. Esto es muy útil para detectar malware
de actores avanzados que hacen uso de técnicas de inyección de procesos para
pasar desapercibidos en el entorno objetivo.

Como entrada puede: manejar archivos de sysmon en formato .evtx, leer el 
registro de sysmon local de máquina donde se ejecuta o incluso trabajar en 
tiempo real en modo demonio leyendo los registros de Sysmon conforme se van 
produciendo.

Cuando una alerta se genera esta se registra en: el log de aplicación del 
sistema, por pantalla en la salida estandar o en un fichero de log en texto
plano.

## Comenzando 🚀
### Intro - Uso ⌨️

Syspce puede utilizarse con diversas finalidades:

1. Para acciones forenses cuando se ha recuperado un archivo .evtx de un 
	equipo afectado o sospechoso.
	
2. Como motor de correlación local en tiempo real que remita sus alertas 
	a un sistema SIEM.
	
3. Como herramienta para probar reglas de correlación previas a su 
	implementación en un sistema de correlación como SPLUNK, QRADAR...

### Pre-requisitos 📋

 - Python 2.7
 - pywin32 227

### Instalación 🔧

1. Desplegamos Python 2.7 de la web oficial [Python Download](https://www.python.org/download/releases/2.7/)
2. Instalamos dependencia con Pip
```
pip install pywin32
```
3. El entorno esta listo, pero antes necesitamos saber un par de cosas más...

El correlador presenta 3 ficheros de configuración donde se pueden definir 
sus reglas:

- baseline.rules : configuración de la normalidad de los procesos
- detection.rules : configuración de las reglas de jerarquia
- detection.macros : definición de grupos de elementos utilizable en los 
dos ficheros de configuracion anteriores

Previa a la ejecución del correlador y para que sea capaz de encontrar el 
fichero local de log dentro de la estructura del eventlog es necesario 
añadir una clave de registro haciendo doble click en el fichero:

	#registry_key.reg
	
Esto es debido a que la libreria de lectura del eventlog de python no es capaz
de trabajar en rutas diferentes a la localizada en los registro System y 
Security.

Acto seguido podemos ejecutar el correlador de la siguiente manera para leer
del registro de sysmon del propio equipo:

	#python sysmonCorrelator.py	
	
```
24/01/2020 11:12:09  [WARNING] Using default Sysmon config schema 3.4
24/01/2020 11:12:09  [INFO] Total events: 236137
24/01/2020 11:13:12  [INFO] Building process tree finished
24/01/2020 11:13:12  [INFO] Total number of process for machine localhost: 6
24/01/2020 11:13:12  [INFO] Total number of connections for machine localhost: 6
24/01/2020 11:13:12  [INFO]
```

Destacar que debido a las diferentes versiones de Sysmon, es necesario
especificar la versión de Schema utilizada mediante el parámetro -s , de no
indicarse utilizará por defecto la versión 3.4. Para obtener el esquema de la 
versión de Sysmon que estemos utilizando se puede ejecutar el siguiente 
comando en la herramienta Sysmon:

	#sysmon -s > schemaVersion.xml

A continuación lanzamos el corerlador con el parámetro -s nuevamente. 

	#python sysmonCorrelator.py -s schemaVersion.xml

Si queremos ejecutar el correlador contra un fichero .evtx previamente obtenido,
podemos ejecutar las siguientes opciones.

	#python sysmonCorrelator.py -s schemaVersion4.21.xml -f sysmonlog.evtx
	
```
[INFO] Using schema sysmonSchema4.21.xml for log parsing
[INFO] Total events: 363
[INFO] Building process tree finished
[INFO] Total number of process for machine localhost: 100
[INFO] Total number of connections for machine localhost: 0
[INFO]
[INFO] PHE ALERT [3]: Lssas child with inyected code
[INFO] --> PROCESS CREATED (480) \SystemRoot\System32\smss.exe
[INFO] ------> [A] CHILD PROCESS CREATED C:\Windows\System32\autochk.exe
[INFO] ------> [A] CHILD PROCESS CREATED C:\Windows\System32\smss.exe
[INFO] ------> [A] CHILD PROCESS CREATED C:\Windows\System32\smss.exe
[INFO] ----> PROCESS CREATED (556) \SystemRoot\System32\smss.exe 00000070 
[INFO] --------> [A] PROCESS TERMINATE C:\Windows\System32\smss.exe
[INFO] --------> [A] CHILD PROCESS CREATED C:\Windows\System32\csrss.exe
[INFO] --------> [A] CHILD PROCESS CREATED C:\Windows\System32\wininit.exe
[INFO] ------> PROCESS CREATED (644) wininit.exe
[INFO] ----------> [A] OPEN REMOTE PROCESS C:\Windows\system32\lsass.exe
[INFO] ----------> [A] OPEN REMOTE PROCESS C:\Windows\system32\lsass.exe
[INFO] ----------> [A] CHILD PROCESS CREATED C:\Windows\System32\services.exe
[INFO] ----------> [A] CHILD PROCESS CREATED C:\Windows\System32\lsass.exe
[INFO] --------> PROCESS CREATED (748) C:\Windows\system32\lsass.exe
[INFO] ------------> [A] STARTED THREAD CREATED FROM REMOTE PROCESS Inyeccion.exe
[INFO] ------------> [A] PROCESS WAS OPENED BY C:\Windows\system32\wininit.exe
[INFO] ------------> [A] PROCESS WAS OPENED BY C:\Windows\system32\csrss.exe
[INFO] ------------> [A] PROCESS WAS OPENED BY C:\Windows\system32\wininit.exe
[INFO] ------------> [A] PROCESS WAS OPENED BY C:\Windows\system32\services.exe
[INFO] ------------> [A] PROCESS WAS OPENED BY C:\Users\p\Desktop\Inyeccion.exe
[INFO] ------------> [A] PROCESS WAS OPENED BY C:\Windows\system32\wbem\wmiprvse.exe
[INFO] ------------> [A] CHILD PROCESS CREATED C:\Windows\System32\cmd.exe
[INFO] ----------> PROCESS CREATED (944) "C:\windows\system32\cmd.exe"  /C notepad
[INFO] --------------> [A] CHILD PROCESS CREATED C:\Windows\System32\conhost.exe
[INFO] --------------> [A] CHILD PROCESS CREATED C:\Windows\System32\notepad.exe
```
Podemos tambien mediante el comando -d dejar al correlador trabajando en 
tiempo real detectando conforme se producen los eventos en el sistema.

	#python sysmonCorrelator.py -s schemaVersion4.21.xml -d

Si además queremos activar el motor de detección de normalidad (baseline)
le añadiremos el parámetro -b.

	#python sysmonCorrelator.py -s schemaVersion4.21.xml -d -b


## Acciones registradas por el correlador 🔩

Cada vez que un proceso se crea este es almacenado en una estructura tipo
arbol donde cada nodo representa un proceso y el vínculo de parentesco
padre-hijo marca sus relaciones. Cada vez que se regitra un Event ID de Sysmon
este se asocia como una acción al nodo/proceso correspondiente. 

Las acciones que se registran son todas aquellas de Sysmon que presentan un 
identificado GUI de proceso y que son las siguientes:

```
'1','2', '3', '5','7','8','9','10','11','12','13','14','15', '17','18','22'
```

Existen 2 acciones (8 CreateRT y 10 OpenP) en las cuales interviene tanto un 
proceso origen como uno destino por lo que en el proceso destino se asocia 
una nueva acción 108 o 110 respectivamente. Esto ayuda a la hora de crear reglas
donde se busca una acción sobre un proceso destino.

```
108 ->> "[A] STARTED THREAD CREATED FROM REMOTE PROCESS" 

	'SourceProcessGuid': Guid del proceso causante de la inyección (inyector)
	'ProcessGuid' : Guid del proceso que ha recibido la inyección 
	'SourceImage': Imegen del proceso causante de la inyección (inyector)
	'Image': Imagen en disco del proceso que ha recibido la inyección 
	'SourceProcessId': Process Id del proceso causante de la inyección 
	'ProcessId': Process Id  del proceso que ha recibido la inyección 
	'SourceSession': SessionID del proceso origen que realiza la inyección
	'SourceIntegrityLevel': Integridad del proceso origen que realiza la 
						inyección
	'SourceUser': Ussurio del proceso origen que realiza la inyección
```
```
110 ->> "[A] PROCESS WAS OPENED BY"

	'SourceProcessGuid': GUID del proceso que realiza la apertura 
	'ProcessGuid': GUID del proceso que ha recibido la apertura 
	'SourceImage': TargetImage del proceso que realiza la apertura 
	'SourceProcessId': Process Id del proceso causante de la apertura
	'Image': Image del proceso que ha recibido la apertura 
	'SourceSession': SessionID del proceso origen que realiza la apertura
	'SourceIntegrityLevel': Integridad del proceso origen que realiza la 
						apertura
	'SourceUser': Ussurio del proceso origen que realiza la apertura
```

Al margen de estas, el correlador genera una más propia '100' que registra la
acción de creación de un proceso hijo en el padre.

```
100 ->> "[A] CHILD PROCESS CREATED" 

	'ChildProcessGuid': GUID del proceso hijo
	'ChildProcessId': PID del proceso hijo
	'ChildCommandLine':  CommandLine del proceso hijo
	'ChildImage': Imagen del proceso hijo
	'ProcessGuid': GUID del proceso que crea el hijo
```

Por lo tanto cuando se crea un proceso, se le asigna una acción de tipo 1 
al proceso creado y una de tipo 100 al proceso padre.

Los siguientes event IDs presentan atributos enriquecidos que permiten 
ampliar las capacidades originales de Sysmon para la correlacion.

```
8 ->> "[A] CREATE REMOTE THREAD TO" y 10 ->> "[A] CREATE REMOTE THREAD TO" 

	'TargetSession': SessionID del proceso al que se le realiza la inyección 
	'TargetIntegrityLevel': Integridad del proceso al que se le realiza la 
						inyección 
	'TargetUser': Ususrio del proceso al que se le realiza la inyección 
```

## Motores de correlación ⚙️

El sistema implementa dos motores de corelación diferentes: uno basado en la 
jerarquia de los procesos "Process Hierarchy Engine" y otro basado en la 
definición de la normalidad de las acciones y caracteristicas de los procesos
en función de una linea base predefinida, "Baseline Engine". Ambos presentan 
un fichero de configuración y reglas con significados diferentes.


### Process Hierarchy Engine

Este motor de correlación permite relacionar e identificar anomalias en flujos
de acciones que realizan los procesos de un equipo.

Para ello se construye el arbol de ejecución de procesos, donde cada nodo del
arbol representa un proceso con la asociación de parentesco padre->hijo
```
Ej. System -> smss.exe -> wininit.exe -> Services.exe -> svchost.exe
```
Estos a su vez tienen como atributos las acciones que estos realizan (Ej. 
creacion de conexion, escritura en registro, etc.). 

Mediante el fichero de reglas de correlacion "detection.rules", es posible 
definir la cadena de acciones que deseamos detectar. Las acciones que se 
registran son todas aquellas de sysmon que presentan un identificado GUI de 
proceso:

```
'1','2', '3', '5','7','8','9','10','11','12','13','14','15', '17','18','22'
```

El fichero es de tipo JSON, donde cada elemento es un diccionario de una clave.
Esta clave representa el tipo de accion de sysmon (1:creacion de proceso,
3: creacion de conexion...) y a continuacion se detallan sus parámetros de 
filtrado, los cuales se usarán para hacer un matching con el proceso concreto
que realiza la acción. (por ejemplo para el tipo 1 es el nombre del proceso).
Las acciones se matchean de forma secuencial. Por ejemplo:

```
{"RuleID":9, "Rulename":"Successful phising attack", "Content": 
				[{'1':{'Image':'Outlook.exe'}},
				{'1':{'CommandLine':'winword.exe'}},
				{'1':{'Image':'cmd.exe'}},
				{'3c':{'DestinationPort':'*', 'DestinationIp':'8.8.8.8'}}
				]}
```

De esta manera se buscara en todo el arbol de procesos la ejecucion de las 
siguientes acciones: 

1. Se crea un proceso Outlook.exe
2. Como hijo de este, se genera un proceso winword.exe
3. Como hijo de este, se genera un proceso cmd.exe
4. Como hijo de este, se genera un proceso que realiza una acción de tipo
	conexion a cualquier puerto a la ip por ejemplo 8.8.8.8. 
	
Del ejemplo anterior existen tres cosas destacables:

- Primero, la "c" (del 3c) significa que buscará una conexión producida por 
cualquiera de los procesos descendientes de cmd.exe dentro del subarbol de ese 
proceso. Si solo queremos indicar que la conexion la relice explicitamente el 
proceso cmd.exe, entonces no se pone la "c". El criterio de matcheo en la 
busqueda es "contiene" lo especificado en el valor de la clave.

- Segundo, es posible especificar varios criterios de filtrado para una misma 
accion, observar en el ejemplo la acción '3c'. Esta solo coincidira con
conexiones cuyo destino sea 8.8.8.8 y sea cualquier puerto destino.

- Tercero, se puede utilizar el caracter comodín * que hara match con cualquier
cosa.

La primera accion dentro del vector de anomalias siempre deberá ser de tipo "c"
ya que buscara a partir del nodo raiz el primer criterio que haga match. Este
tipo de modificador nos añade la potencia de detectar acciones concretas 
que hagan todos los procesos hijos de un proceso sin importar el grado por 
debajo de la jerarquia. Una regla tradicional de correlación que detectara 
estrictamente lo siguiente en busca de un phising como:
```
[outlook] -> [winword] -> [cmd] -> [wscript] (hace una conexion para el dropeo)
```
Sería facilmente bypaseable desde el punto de vista de ataque llamando por 
ejemplo de forma intermedia a un Lolbin.
```
[outlook] -> [winword] -> [forfiles] -> [cmd] -> [wscript] (Conexion)
```																
Las conbinaciones de posibles bypasses son infinitas, pero lo que al final nos
importa es que algín hijo de winword que provenga de una ejecución por correo
realice una conexión a Internet, no importa el grado de descendencia que 
tenga en la relación de parentesco. Ese hecho es sí es muy sospechoso, por lo que 
de forma generalizada podemos modelar la amenaza de la siguiente forma con el 
correlador:
```
{"RuleID":9, "Rulename":"Successful phising attack", "Content": 
				[{'1':{'Image':'Outlook.exe'}},
				{'1':{'CommandLine':'winword.exe'}},
				{'3c':{'DestinationPort':'*'}}
				]}
```			
 Es más haciendo uso de las macros que más adelante se explican, es posible
 en una única regla definir un ataque de phising cubriendo todos los posibles
 casos de diferentes procesos.

```
 {"RuleID":9, "Rulename":"Successful phising attack", "Content": 
				[{'1':{'Image':'EMAIL_AGENTS'}},
				{'1':{'CommandLine':'OFFICE_PROCESS'}},
				{'3c':{'DestinationPort':'*'}}
				]}
 
```
Cada linea del "content" de la regla de correlación representa las acciones que 
realiza un proceso. Se pueden indicar varias acciones (ids de sysmon) asociadas
a un proceso. Ejemplo.
```
{"RuleID":3, "Rulename":"Lssas child with inyected code", "Content": [ 
	{"1c":{"Image":"lsass", "ParentCommandLine":"wininit"}, "108c":{"Image":"lsass"} },
	{"1":{"Image":"*"}}
	]},
```
Esta regla haria:
1. Busca un proceso llamado lsass cuyo padre sea winint y haya 
	recibido (108) una orden de crear un hilo por parte de otro proceso.
  ```
  {"1c":{"Image":"lsass", "ParentCommandLine":"wininit"}, "108c":{"Image":"lsass"} }
  ```
2. El proceso lsass genera un hijo directo de cualquier tipo.
  ```
  {"1":{"Image":"*"}}
  ```
Tambien se pueden usar negadores tanto en los Id de acción como en los atributos

```
{"RuleID":5, "Rulename":"Suspicious Office process parent", "Content": [ 
	{"1c":{"Image":"OFFICE_PROCESS", "-ParentCommandLine":"OFFICE_NORMAL_PARENTS"}}
	]},	
```
Esta regla detectaria si se crea un proceso de office cuyo padre no esta en la 
lista de sus padres normales alerta.

Todo valor de los atributos que es escrito en mayusculas representa una macro, 
que no es más que un conjunto de valores definidos en el fichero "detection.macros"
Esto agiliza la escritura de reglas considerablemente. Por lo tanto si 
observamos el ejemplo anterior y el valor de las macros alli definidas vemos:
```
"OFFICE_NORMAL_PARENTS":["svchost.exe",
                         "explorer.exe",
                         "cmd.exe"
                         ],
                         
"OFFICE_PROCESS":["winword.exe",
                  "powerpnt.exe",
                  "excel.exe",
                  "outlook.exe",
                  "msaccess.exe"
                  ],	
```					
La regla por tanto combina cada uno de los valores anteriores, es decir:

Si winword.exe no tiene como padre o svchost.exe o explorer.exe o cmd.exe
Si powerpnt.exe no tiene como padre o svchost.exe o explorer.exe o cmd.exe
etc..

Si la negación se realiza sobre el ID de acción negará todo los atributos a los
que afecte, por ejemplo.
```
{"RuleID":8, "Rulename":"Cross session process creation 1->0", "Content": [ 
				{"1c":{"TerminalSessionId":"1"}},
				{"-1":{"TerminalSessionId":"1", "Image":"svchost.exe"}}
        ]}
```
Esta regla haría:

1. Encuentra un proceso que se haya creado en la sesion de usuario 1
2. Crea como hijo un proceso en otra sesion diferente a la 1 y con nombre
	de imagen diferente a svchost.exe

Al margen de lo anterior el correlador es capaz de detectar cuando un proceso
es creado por un hilo generado por una inyección de codigo realizada con la 
técnica de CreateRemoteThread (ID 8), es decir:
```
1)  PROCESS_A ----CreateRemoteThread X in --> PROCESS_B
	
2)  PROCESS_B (Thread X) ----CreateProcess--> PROCESS_C
```
Pare ello se correlan automaticamente los ids 8, 10 y 1 de sysmon.
Esto nos permite añadir un atributo nuevo a las acciones de tipo 1 asociadas
a un proceso y que son:

```
"CreationType": RegularThread (hilo normal), InjectedThread (hilo creado por una inyección de código)
		
"RealParent": PID e imagen del proceso real que ha creado el hijo
```
Por lo tanto en las reglas de detección del motor de jerarquia podemos indicar
que queremos alertar procesos creados por hilos inyectados Ej.
```
{"RuleID":3, "Rulename":"Precess created by injected Thread", "Content": [
                    {"1c":{"CreationType":"InjectedThread"}}
                    ]}
```									
Un ejemplo de resultado de ejecución con un positivo en detección sería el 
siguiente:
```
[INFO] Using schema sysmonSchema4.23.xml for log parsing
[INFO] Total events: 5
[INFO] Building process tree finished
[INFO] Total number of process for machine localhost: 2
[INFO] Total number of connections for machine localhost: 0
[INFO]
[INFO] PHE ALERT [3]: Precess created by injected Thread
[INFO] --> PROCESS CREATED (2748) C:\Windows\Explorer.EXE
[INFO] ------> [A] OPEN REMOTE PROCESS C:\windows\system32\cmd.exe
[INFO] ------> [A] STARTED THREAD CREATED FROM REMOTE PROCESS C:\Users\p\Desktop\Inyeccion.exe
[INFO] ------> [A] IMAGE LOADED C:\Users\p\AppData\Roaming\sysmon-inyecciondll.dll
[INFO] ------> [A] CHILD PROCESS CREATED C:\Windows\System32\cmd.exe
[INFO] ----> PROCESS CREATED (1468) "C:\windows\system32\cmd.exe"  /C c:\windows\system32\notepad.exe
[INFO] --------> [I] REAL PARENT (2468) C:\Users\p\Desktop\Inyeccion.exe
[INFO] --------> [A] PROCESS WAS OPENED BY C:\Windows\Explorer.EXE
[INFO]
[INFO]
```
Tambien es posible definir que un conjunto de acciones dentro de la jerarquia 
se realice "n" veces en un periodo de tiempo, definido de esta manera.
```
{"N":[veces], "Seconds":[tiempo en segundos]}  
```
Por ejemplo: la secuencia siguiente busca un proceso wininit y lo que viene 
definido a partir de la marca temporal solo se alertara si se repite 2 veces. 
```
{"1c":{"Image":"wininit.exe",},
{"N":3, "Seconds":86400},
{"1":{"Image":"lsass.exe"}},
{"1":{"Image":"werfault.exe"}}
```
Es decir el flujo de ejecucion seria:
```
wininit PID 1 -> lsass PID 1 -> werfault PID 1
wininit PID 1 -> lsass PID 2 -> werfault PID 2
wininit PID 1 -> lsass PID 3 -> werfault PID 3
	
Alerta! Esta regla busca inyecciones sobre el lsass que hayan podido crashearlo.
```
De la misma forma podemos definir el diccionario de repetición/temporalidad
al principio de la regla:
```
{"N":3, "Seconds":900},
{"1c":{"TerminalSessionId":"0", "Image":"WEB_BROWSERS"}} 
```
En este ejemplo saltara una alerta si se crean en un periodo de 15min 3 o más
procesos de navegadores web en sesion de servicios (Sesión 0).

### Baseline Engine 

El segundo motor de correlación presenta una aproximación diferente, trata 
de modelar mediante el fichero de configuración de reglas "baseline.rules" el
comportamiento normal de los procesos para identificar cuando se produce una 
anomalía por acciones que normalmente no suelen realizar. Por ejemplo,
no es habitual que el proceso lssas.exe cree hijos,  pero sí escribir en 
ciertos registros de windows conocidos. Con esta estrategia se pretende sobretodo
detectar acciones de adversarios avanzados que utilicen tecnicas de inyección 
de procesos que hacen más sigilosas sus acciones maliciosas. Algunas de las
heramientas que se analizan especificamente son Cobalt-strike y Meterpreter de
Metasploit.

El motor utiliza un sistema de puntos asociados a los procesos. Cada proceso
tiene 100 puntos y por cada acción que se realiza fuera de su normalidad se
le resta una cantidad que es definida en cada acción en su configuración. Si un
proceso llega a tener 0 puntos durante su ejecución o incluso un valor negativo 
se alerta.

A continuación com ejemplo se muestra la definición de la normalidad del
proceso explorer.exe
```
[{"explorer.exe":{"max_ttl": 1000000, "min_ttl": 20, "Points": 10,
    "1":{"Points": 100,
         "Image":{"Points": 75, "Value": "C:\\Windows\\explorer.exe"},
         "ParentImage":{"Points": 50, "Value": "EXPLORER_PARENT_IMAGE"},
         "-User":{"Points": 40, "Value": "system"}
         },
							
    "100":{"Points": 10},
		
    "2":{"Points": 10,
         "TargetFilename":{"Points": 100, "Value": "AppData"}
         },
    
    "3":{"Points": 10, "N": 20, "Seconds": 3600,
         "DestinationPort": {"Points": 50, "Value": "EXPLORER_DST_PORTS"}
         },
         
    "7":{"Points": 10,
         "ImageLoaded": {"Points": 10, "Value": "EXPLORER_IMAGE_LOADED_PATH"},
         "SignatureStatus": {"Points": 50, "Value": "MODULE_SIGNATURE_STATUS"}
         },
         
    "-8":{"Points": 100},
		
    "-108":{"Points": 50},
		
    "9":{"Points": 10,
         "Device":{"Points": 100, "Value": "\\Device\\HarddiskVolume"}
         },
												
    "10":{"Points": 10},
						
    "110":{"Points": 10,
           "TargetImage":{"Points": 10, "Value": "EXPLORER_ACCESS_PROCESS_SOURCE_PROCESS"}
           },
			
    "11":{"Points": 10},
		
    "12":{"Points": 10},
		
    "13":{"Points": 10,
          "TargetObject":{"Points": 10, "Value": "EXPLORER_REG_TARGET_OBJECT"}
          },
          
    "-17":{"Points": 50},		
						
    "18":{"Points": 10,
          "PipeName":{"Points": 50, "Value": "EXPLORER_PIPES"}
          }	
    }
}]
```
En la primera linea observamos:
```
{"explorer.exe":{"max_ttl": 1000000, "min_ttl": 20, "Points": 10,
```
El proceso que se modela es explorer.exe y tiene un tiempo de vida normal de 
entre 20 segundos y 1000000 segundos, si el proceso no dura ese tiempo se le 
restaria la contidad de 10 puntos. A continuación vemos la definición de la 
creación de proceso (ID 1):
```
"1":{"Points": 100,
     "Image":{"Points": 75, "Value": "C:\\Windows\\explorer.exe"},
     "ParentImage":{"Points": 50, "Value": "EXPLORER_PARENT_IMAGE"},
     "-User":{"Points": 40, "Value": "system"}
     },
```
Se establece una puntuación por defecto de -100 puntos ("Points": 100) 
si no se especifica ninguna en los atributos concretos. Definimos que 
su "Imagen" en disco simpre reside en  "C:\\Windows\\explorer.exe", sino lo 
estuviera restamos 75 puntos. Si su proceso padre no esta en la lista de las 
macros definidas en EXPLORER_PARENT_IMAGE restaremos 50 puntos. Definimos por 
último que el usuario que lo ejecuta normalmente no es SYSTEM. En caso de que
lo sea restamos 40 porque no es normal que un explorer (que es la shell del 
usuario) sea ejecutada por el usuario de la máquina (SYSTEM).

La siguiente linea identifica que el explorer.exe normalmente crea hijos.
Cuando se produce un ID 1 se asocia como accion al proceso creado
y a su padre se le crea una entrada de acción ID 100 como creador. Por lo 
tanto si tenemos un proceso explorer que tras su finalización no ha generado
hijos restaremos 10 puntos ya que no es habitual que esto no se produzca.
```
"100":{"Points": 10},
```
Las siguientes acciones 2, 3 y 7 definen la normalidad de las acciones de 
esa tipologia. En este caso el EventId 3 presenta una nueva funcionalidad 
mediante los atributos "N" y "Seconds", que dota al correlador de la capacidad
de definir el número de acciones máximas que un proceso puede hacer en un 
rango temporal. Para este caso concreto se indica que el proceso explorer 
normalmente hace no mas de 20 conexiones a los puertos destinos especificados
en la macro EXPLORER_DST_PORTS en períodos de tiempo de 1h (3600 segundos).
En el caso de que se exceda este valor se restarán 10 puntos al proceso,
sumando por tanto acciones anómalas al mismo.
```
"2":{"Points": 10,
     "TargetFilename":{"Points": 100, "Value": "AppData"}
     },

"3":{"Points": 10, "N": 20, "Seconds": 3600,
     "DestinationPort": {"Points": 50, "Value": "EXPLORER_DST_PORTS"}
     },
						
"7":{"Points": 10,
     "ImageLoaded": {"Points": 10, "Value": "EXPLORER_IMAGE_LOADED_PATH"},
     "SignatureStatus": {"Points": 50, "Value": "MODULE_SIGNATURE_STATUS"}
     }
```
A continuación se establece que el proceso explorer normalmente no debe realizar
acciones de creación remota de hilos (ID 8 ) ni debe recibir acciones de lanzar
nuevos hilos a petición de otro proceso. Esto lo indicamos con el signo "-" que
niega la acción. Si en algun momento se pruduce este tipo de actividad restará
100 puntos en el caso del ID 8 y 50 en el del ID 108.
```
"-8":{"Points": 100},
		
"-108":{"Points": 50},
```
Las dos siguientes determinan que el proceso habitualmente abre procesos 
remotos ID 10 y accede a dispositivos de forma "Raw" ID 9.
```
"9":{"Points": 10,
     "Device":{"Points": 100, "Value": "\\Device\\HarddiskVolume"}
     },
												
"10":{"Points": 10},
```
La siguiente entrada identifica que el proceso explorer.exe recive normalmente
solicitudes de acceso al manejador del proceso (OpenProcess ID 10), por parte 
de los procesos recogidos en la macro EXPLORER_ACCESS_PROCESS_SOURCE_PROCESS.
Recordar que se registra un ID 10 en el proceso que hace el Openprocess y un 
ID 110 en el proceso que recibe la apertura.
```
"110":{"Points": 10,
       "TargetImage":{"Points": 10, "Value": "EXPLORER_ACCESS_PROCESS_SOURCE_PROCESS"}
       },
```		
El resto de IDs no presentan novedades de funcionalidad con respecto a lo 
comentado anteriormente.

```
"11":{"Points": 10},
		
"12":{"Points": 10},
		
"13":{"Points": 10,
      "TargetObject":{"Points": 10, "Value": "EXPLORER_REG_TARGET_OBJECT"}
      },
      
"-17":{"Points": 50},		
						
"18":{"Points": 10,
      "PipeName":{"Points": 50, "Value": "EXPLORER_PIPES"}
      }
```
Existe un ID especial para el correlador que dispara una logica de comprobación
adicional, este es el ID 5 (Process Terminate). Cuando un proceso termina 
se comprueban 2 cosas:

1. Que todas las acciones qeu normalmente deberia de hacer se han realizado,
	es decir, si en la configuración teniamos definido que por ejemplo explorer
	escribe en el registro y este no lo ha hecho, se restarán los puntos 
	definidos para esa acción concreta.
	
2. Se calcula el TTL del proceso, es decir su tiempo de vida y se compara
	con el definido en su configuración, en la primera linea:
	```
	{"explorer.exe":{"max_ttl": 1000000, "min_ttl": 20, "Points": 10,
	```
	Explorer es normal que al menos dure más de 20 segundos y no mas de un 
	valor muy alto commo es 1000000 segundos, ya que esta shell de usuario, a 
	menos que haya un crash del proceso no suele terminar o salvo que se apague 
	la máquina. Esta estrategia de detección es muy útil para identificar 
	procesos Dummy creados por Cobal-Strike para ejecutar en memoria modulos
	de post-explotación.
	
Destacar que si no definimos alguna de las acciones o IDs del conjunto que el
correlador soporta, esta simplemente no se procesará. Esto se ha de tener
en espacial en cuenta cuando nustra configuración de Sysmon no registre o 
tenga deshabilitado por configuración algun tipo de ID concreto. Es habitual
que por ejemplo el ID 10 se deshabilite complentamente debido al gran volumen 
de alertas que genera.

## Otras funcionalidades ⌨️

Con el objetivo de poder buscar en una investigacion o proceso de hunting de 
forma rapida, atributos o events ID concretos en un evtx de sysmon. La 
aplicación dispone de un filtro de busqueda mediante el parametro -e. 
```
#python sysmonCorrelator.py -f "sysmon.evtx" -e "{'CommandLine':'bypass', 'idEvent':1}"
```
El ejemplo anterior lista todos los eventos de tipo creación de proceso que
contengan en la linea de comandos la palabra "bypass". Se aplica un AND en el 
filtro y los valores no distinguen de mayusculas o minusculas. El resultado
muestra todos los atributos de un evento que hace match con el filtro de 
busqueda.
```
{'CommandLine': 'powershell.exe -ExecutionPolicy ByPass -File C:\NagScripts.ps1',
 'CurrentDirectory': u'C:\\PROGRA~2\\HEWLET~1\\HPCA\\Agent\\',
 'Hashes': 'SHA1=E5B0A0F4A59D6D5377332EECE20F8F3DF5CEBE4E',
 'Image': u'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
 'IntegrityLevel': u'System',
 'LogonGuid': u'{83a0deeb-f736-5e02-0000-0020e7030000}',
 'LogonId': u'0x3e7',
 'ParentCommandLine': u'"C:\\PROGRA~2\\HEWLET~1\\HPCA\\Agent\\hide.exe"',
 'ParentImage': u'C:\\PROGRA~2\\HEWLET~1\\HPCA\\Agent\\hide.exe',
 'ParentProcessGuid': u'{83a0deeb-8478-5e27-0100-001058498b2d}',
 'ParentProcessId': u'833468',
 'ProcessGuid': u'{83a0deeb-8478-5e27-0100-0010514c8b2d}',
 'ProcessId': u'815284',
 'TerminalSessionId': u'0',
 'User': u'NT AUTHORITY\\SYSTEM',
 'UtcTime': u'2020-01-21 23:08:40.943',
 'computer': 'localhost',
 'idEvent': 1} 
```
Si no queremos ver todos los atributos por pantalla se puede usar el parámetro
"-a atributo" para mostrar solo los atributos de ese tipo. El comando siguiente
mostraria solo los de tipo "CommandLine"
```
#python sysmonCorrelator.py -f "sysmon.evtx" -e "{'CommandLine':'bypass', 'idEvent':1}" -a CommandLine
```
La búsqueda se puede hacer sobre un fichero .evtx como en los ejemplos 
anteriores o sobre el log propio de sysmon del equipo donde se ejecuta el
correlador, simplemente no pasandole el nombre del fichero.
```
#python sysmonCorrelator.py  -e "{'CommandLine':'bypass', 'idEvent':1}"
```

## TODO LIST 🛠️

-[General] Motor de correlación basado en acciones temporales y no por relación
de procesos.

-[Jerarquia] Detectar cuando una accion se produce n veces en un rango de 
tiempo.
```
Ej. Proceso 1 genera carga dll 1
    Proceso 1 genera carga dll 2
    Proceso 1 genera carga dll 3
    Proceso 1 genera carga dll 4
```
-[GENERAL] Añadir al Id 3 la geolocalización y el nombre de la orgnización 
asociada  a una IP. Permitirá hacer reglas del tipo si un proceso explorer.exe
hace conexiones que no van a una IP de microsoft (posible codigo inyectado). 

-[GENERAL] Añadir tipo de proceso como caracteristica : service, scheduledTask,
														regularProcess
-[Jerarquia] poder buscar por TTL de los procesos

## Autor ✒️
* **Roberto Amado** - *Desarrollo e inteligencia de detección* - [@ramado78](https://twitter.com/ramado78)
  * **Presentaciones** - *Rootedcon 2020 presentación* [pdf](https://t.co/aSjG6CpG6s?amp=1) 
