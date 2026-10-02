# Unit systemd del controllo periodico

Copiare in `/etc/systemd/system/`, poi:

    sudo systemctl daemon-reload
    sudo systemctl enable --now modemproxy-health.timer
    sudo systemctl enable modemproxy-health-boot.service

`modemproxy-health.timer` usa `OnCalendar=*:0/15`, non `OnUnitActiveSec`:
quest'ultimo pianifica a partire dall'ultima esecuzione del servizio, quindi
su un servizio mai eseguito il timer resta attivo ma non parte mai. E'
successo davvero (installato il 20/09/2026, zero esecuzioni fino al
02/10/2026), e nel frattempo un guasto reale — le regole di port mapping del
router passate in errore — non e' stato segnalato.

Verifica rapida che sia pianificato davvero:

    systemctl list-timers | grep health     # deve mostrare un orario in NEXT
