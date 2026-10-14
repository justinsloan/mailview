; Register MailView under "Open with" for its message formats without taking
; over the default app. electron-builder's own fileAssociations would make
; MailView the default handler, so the keys are written here instead.
; SHELL_CONTEXT is HKCU for a per-user install and HKLM for a per-machine one.

!define MAILVIEW_PROGID "MailView.Message"

!macro mailviewRegisterExt EXT
  WriteRegNone SHELL_CONTEXT "Software\Classes\${EXT}\OpenWithProgids" "${MAILVIEW_PROGID}"
  WriteRegStr SHELL_CONTEXT "Software\Classes\Applications\${APP_EXECUTABLE_FILENAME}\SupportedTypes" "${EXT}" ""
!macroend

!macro mailviewUnregisterExt EXT
  ; Only remove our own value. The extension keys belong to the system and to
  ; other apps (DeleteRegKey /ifempty would still delete keys that hold values).
  DeleteRegValue SHELL_CONTEXT "Software\Classes\${EXT}\OpenWithProgids" "${MAILVIEW_PROGID}"
!macroend

!macro customInstall
  WriteRegStr SHELL_CONTEXT "Software\Classes\${MAILVIEW_PROGID}" "" "Email message (MailView)"
  WriteRegStr SHELL_CONTEXT "Software\Classes\${MAILVIEW_PROGID}\DefaultIcon" "" "$INSTDIR\${APP_EXECUTABLE_FILENAME},0"
  WriteRegStr SHELL_CONTEXT "Software\Classes\${MAILVIEW_PROGID}\shell\open" "FriendlyAppName" "MailView"
  WriteRegStr SHELL_CONTEXT "Software\Classes\${MAILVIEW_PROGID}\shell\open\command" "" '"$INSTDIR\${APP_EXECUTABLE_FILENAME}" "%1"'

  WriteRegStr SHELL_CONTEXT "Software\Classes\Applications\${APP_EXECUTABLE_FILENAME}" "FriendlyAppName" "MailView"
  WriteRegStr SHELL_CONTEXT "Software\Classes\Applications\${APP_EXECUTABLE_FILENAME}\DefaultIcon" "" "$INSTDIR\${APP_EXECUTABLE_FILENAME},0"
  WriteRegStr SHELL_CONTEXT "Software\Classes\Applications\${APP_EXECUTABLE_FILENAME}\shell\open\command" "" '"$INSTDIR\${APP_EXECUTABLE_FILENAME}" "%1"'

  !insertmacro mailviewRegisterExt ".eml"
  !insertmacro mailviewRegisterExt ".emlx"
  !insertmacro mailviewRegisterExt ".msg"
  !insertmacro mailviewRegisterExt ".mht"
  !insertmacro mailviewRegisterExt ".mhtml"

  System::Call 'shell32::SHChangeNotify(i, i, i, i) v (0x08000000, 0, 0, 0)'
!macroend

!macro customUnInstall
  !insertmacro mailviewUnregisterExt ".eml"
  !insertmacro mailviewUnregisterExt ".emlx"
  !insertmacro mailviewUnregisterExt ".msg"
  !insertmacro mailviewUnregisterExt ".mht"
  !insertmacro mailviewUnregisterExt ".mhtml"

  DeleteRegKey SHELL_CONTEXT "Software\Classes\${MAILVIEW_PROGID}"
  DeleteRegKey SHELL_CONTEXT "Software\Classes\Applications\${APP_EXECUTABLE_FILENAME}"

  System::Call 'shell32::SHChangeNotify(i, i, i, i) v (0x08000000, 0, 0, 0)'
!macroend
