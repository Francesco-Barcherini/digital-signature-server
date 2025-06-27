# Todo

- [x] Inviare la lunghezza del messaggio cifrato non in chiaro ma come messaggio cifrato a se, avrà una lunghezza prefissata. 
- [ ] (forse fatto) Variabili thread_local per getire le connessioni multiple 
- [x] Check counter overflow per l'IV di AES_GCM
- [ ] Azzerare plaintext e chiavi private dalla memoria dopo l'uso
- [x] Evitare che se un thread muore, muoiono tutti
- [ ] () Gestire Ctrl+C del client
- [ ] Scommentare la exit del server
- [ ] Password oscurata lato client
- [ ] Sistemare LOG
- [ ] Testare bene tutto