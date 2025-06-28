# Todo

- [x] Inviare la lunghezza del messaggio cifrato non in chiaro ma come messaggio cifrato a se, avrà una lunghezza prefissata.
- [x] Variabili thread_local per getire le connessioni multiple
- [x] Check counter overflow per l'IV di AES_GCM
- [x] Azzerare plaintext e chiavi private dalla memoria dopo l'uso (tet)
- [x] Evitare che se un thread muore, muoiono tutti
- [x] Gestire Ctrl+C del client
- [x] Scommentare la exit del server (ave)
- [x] Sistemare LOG
- [x] IV aumenta esattamente di uno (ave)
- [x] Inviare lunghezza cifrato in chiaro (ave)
- [x] Aggiungere padding al messaggio?
- [ ] Testare bene tutto
- [x] Check openssl_API() != 1 e non <=0
- [x] Check API _ex rispetto a quelle usate nei lab
- [ ] Testare su valgrind (DecryptFinal_ex dà problemi)
- [x] RSA con PQ??
- [x] Vedere lunghezza del messaggio (evitare overflow)
- [ ] Fix Decrypt fail on tag
