
-------------
Installation:
-------------
	La commande "make" pour installer l'analyseur
	L'éxecutable sera crée dans le même dossier et qui s'appelle projet0

------------
Execution:
------------
	Le programe s'execute par la commande :
											./projet0

------------
Options:
------------
	L'analyseur peut-être démarré avec quatre options différentes : i,o,f,v
	l'usage est le suivant:
			./sniffex (-i <interface> | -o <file>) [-f <BPF filter>] [-v <1|2|3>(verbosity)>]

	*** o : L'option de choix d'interface permet de choisir l'interface sur laquelle les trames seront analysées.
	*** f : Le filtre permet de filtrer les paquets selon le filtre choisie
	*** o : Le fichier  de trace pour l'analyse offline
	*** v : Niveau de verbosité :
		<1> affichera les infos nécessaires
		<2> affichera quelques lignes en plus
		<3> affichera les détails des trames

----------------------
Exemples d'utilisation
----------------------
./analyseur -o "http.cap"




