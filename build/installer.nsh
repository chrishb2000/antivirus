!macro customInstall
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "Aegis AI Antivirus" '"$INSTDIR\Aegis AI Antivirus.exe" --autostart'
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Aegis AI Antivirus" '"$INSTDIR\Aegis AI Antivirus.exe" --autostart'
!macroend

!macro customUnInstall
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "Aegis AI Antivirus"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Aegis AI Antivirus"
!macroend
