/* REXX */
/* Lists APF LIBS and access */

say "APF Enumeration Script"

NUMERIC  DIGITS 10
CVT      = C2d(Storage(10,4))                /* point to cvt */
CVTAUTHL = C2d(Storage(D2x(CVT + 484),4))    /* point to auth lib tbl*/
If CVTAUTHL <> C2d('7FFFF001'x) then do      /* static list ?        */
  say "Static APF"
  NUMAPF   = C2d(Storage(D2x(CVTAUTHL),2))   /* # APF libs in table  */
  APFOFF   = 2                               /* first ent in APF tbl */
  Do I = 1 to NUMAPF
     LEN = C2d(Storage(D2x(CVTAUTHL+APFOFF),1)) /* length of entry   */
     DSN.I = Storage(D2x(CVTAUTHL+APFOFF+1+6),LEN-6) /*DSN of APF lib*/
     APFOFF = APFOFF + LEN +1
     say DSN.I
  End
End
Else Do  /* dynamic APF list via PROGxx */
  say "Dynamic APF"
  ECVT     = C2d(Storage(D2x(CVT + 140),4))  /* point to CVTECVT     */
  ECVTCSVT = C2d(Storage(D2x(ECVT + 228),4)) /* point to CSV table   */
  APFA = C2d(Storage(D2x(ECVTCSVT + 12),4))  /* APFA                 */
  AFIRST = C2d(Storage(D2x(APFA + 8),4))     /* First entry          */
  ALAST  = C2d(Storage(D2x(APFA + 12),4))    /* Last  entry          */
  LASTONE = 0   /* flag for end of list      */
  NUMAPF = 1    /* tot # of entries in list  */
  /* Get the WARNING DATASETS. */
  W = OUTTRAP('OUTW.')
  ADDRESS TSO "SEARCH ALL WARNING NOMASK"
  W = OUTTRAP('OFF')
  Do forever
     DSN.NUMAPF = Storage(D2x(AFIRST+24),44) /* DSN of APF library   */
     DSN.NUMAPF = Strip(DSN.NUMAPF,'T')      /* remove blanks        */
     say DSN.NUMAPF
     CKSMS = Storage(D2x(AFIRST+4),1)        /* DSN of APF library   */
     If Substr(DSN.NUMAPF,1,1) <> X2c('00')  /* check for deleted    */
       then NUMAPF = NUMAPF + 1              /*   APF entry          */
     AFIRST = C2d(Storage(D2x(AFIRST + 8),4)) /* next  entry          */
     If LASTONE = 1 then leave
     If  AFIRST = ALAST then LASTONE = 1
  End
  NUMAPF = NUMAPF-1
End
exit(0)
