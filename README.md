Beschreibung
monitor_system.py ist ein Python-Skript zur Überwachung von Systemaktivitäten. Es führt eine Reihe von Sicherheits- und Leistungsüberprüfungen durch, einschließlich:

Port-Scanning: Identifiziert offene Netzwerkports und die dazugehörigen Prozesse.
Prozessüberwachung: Überprüft laufende Prozesse auf verdächtiges Verhalten, wie z.B. hohe CPU- oder Speichernutzung, sowie verdächtige Prozessnamen.
Netzwerküberwachung: Überwacht den Netzwerkverkehr und zeigt die Anzahl der gesendeten und empfangenen Bytes an.
Das Skript ist modular aufgebaut und verwendet Clean Code-Prinzipien sowie SOLID-Design-Prinzipien, um wartbaren, testbaren und verständlichen Code zu gewährleisten.

Funktionen
Modulares Design: Der Code ist in klar abgegrenzte Klassen unterteilt, die jeweils eine einzelne Verantwortung haben.
Erweiterbarkeit: Neue Überwachungsfunktionen können leicht hinzugefügt werden, indem zusätzliche Klassen implementiert und in das MonitoringProgram integriert werden.
Fehlerbehandlung: Umfassende Fehlerbehandlung sorgt dafür, dass das Programm auch bei Fehlern stabil bleibt.
Verwendung
Das Skript kann direkt über die Kommandozeile ausgeführt werden:


python system_monitor.py
Das Programm zeigt die aktuellen Überwachungsergebnisse in der Konsole an, einschließlich Warnungen über verdächtige Aktivitäten.

Anforderungen
Python 3.x

psutil Bibliothek

Installiere die benötigte Bibliothek mit:
pip install psutil



Lizenz
Dieses Projekt steht unter der MIT-Lizenz.
