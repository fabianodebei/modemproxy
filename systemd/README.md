
## modemproxy-health.timer

Usa `OnCalendar=*:0/15`, non `OnUnitActiveSec`: quest'ultimo pianifica a
partire dall'ultima esecuzione del servizio, quindi su un servizio mai
eseguito il timer resta attivo ma non parte mai. E' successo davvero
(installato il 20/09/2026, zero esecuzioni fino al 02/10/2026) e nel
frattempo un guasto reale non e' stato segnalato. Verifica:
`systemctl list-timers | grep health` deve mostrare un orario in NEXT.
