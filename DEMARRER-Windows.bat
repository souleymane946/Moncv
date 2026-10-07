@echo off
rem ============================================================
rem  Ouvrir les outils de triage cybersecurite
rem  Double-cliquez simplement sur ce fichier.
rem  Aucune installation, aucun serveur, aucune connexion.
rem ============================================================
echo Ouverture de la page d'accueil dans votre navigateur...
start "" "%~dp0index.html"
echo.
echo Si rien ne s'ouvre : ouvrez le dossier, puis double-cliquez sur index.html
echo ou sur un fichier du dossier standalone.
timeout /t 4 >nul
exit
