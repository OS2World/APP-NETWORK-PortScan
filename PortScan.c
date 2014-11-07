//=============================================================================
// PortScan.c
// Программа сканирования портов хоста IP
//=============================================================================
#define INCL_WIN
#define INCL_DOSPROCESS
#define INCL_DOSERRORS
#define INCL_DOSSEMAPHORES

#include <os2.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <types.h>
#include <sys\socket.h>
#include <sys\ioctl.h>
#include <sys\select.h>
#include <netinet\in.h>
#include <net\if.h>
#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
#include <arpa\inet.h>
#include <unistd.h>
#endif               // TCPV40HDRS
#include <nerrno.h>
#include <netinet/in_systm.h>
#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
#include <netinet\ip.h>
#else
#include "ip.h"
#endif
#include <netinet\ip_icmp.h>
#include <netinet\tcp.h>
#include "PortScan.h"

#define SPORT    1
#define EPORT 1024
#define DEFAULT_TIMEOUT 1
#define MAX_TIMEOUT 99
#define MAXPACKET 768

//-----------------------------------------------------------------------------
// Prototypes
//-----------------------------------------------------------------------------
#define GetParm(ParmID,ParmName) { \
if ( PrfQueryProfileSize(hini, APPNAME, ParmID, &DataLen) ) \
  if ( DataLen == sizeof(ParmName) ) \
    PrfQueryProfileData(hini, APPNAME, ParmID, &ParmName, &DataLen); }

#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
#define myFD_SET(fd, set) { \
    if (((fd_set *)(set))->fd_count < FD_SETSIZE) \
        ((fd_set *)(set))->fd_array[((fd_set *)(set))->fd_count++]=fd; }
#else
#define myFD_SET(fd, set) { FD_SET(fd, set); }
#endif

//-----------------------------------------------------------------------------
// Dialog Window procedure prototype
//-----------------------------------------------------------------------------
MRESULT EXPENTRY DlgMenu (HWND, ULONG ,MPARAM, MPARAM);
void SendErrMsg(HWND, char *);
void SendWngMsg(HWND, char *);
struct sockaddr_in resolv(HWND, char *);
void TestParm(HWND);
void InitContainerTCP(HWND);
void InitContainerUDP(HWND);
void APIENTRY DoScanUDP(ULONG);
void APIENTRY DoScanTCP(ULONG);
void InsertRecordUDP(HWND hwnd, int i);
void InsertRecordTCP(HWND hwnd, int i);
u_short in_cksum(u_short *, int);
BOOL PingTest(HWND);

//-----------------------------------------------------------------------------
// Global Variablies
//-----------------------------------------------------------------------------
int ac;
char **av;
char ErrMsg[96], MsgText[32], UDPtext[16], TCPtext[16],
     SPini[17] = "S", PPini[17] = "P", TOini[17] = "T";
struct sockaddr_in myaddr_udp = { 0 }, myaddr_tcp = { 0 };
struct sockaddr_in whereto = { 0 }; // Who to ping
unsigned short sport, eport, timeout;
unsigned short start_port = SPORT;
unsigned short stop_port = EPORT;
unsigned short icmp_timeout = DEFAULT_TIMEOUT;
char titleaddr[32] = "IP address ";
typedef struct _USERRECORD_TCP
  { RECORDCORE  recordCore;
    PSZ         TCP_Port;
    PSZ         TCP_Service;
  } USERRECORD_TCP, *PUSERRECORD_TCP;
typedef struct _USERRECORD_UDP
  { RECORDCORE  recordCore;
    PSZ         UDP_Port;
    PSZ         UDP_Service;
  } USERRECORD_UDP, *PUSERRECORD_UDP;
HEV hevEventHandleUDP = 0, hevEventHandleTCP = 0;
TID tidUDP = 0, tidTCP = 0;
ULONG ulPostCntUDP = 0, ulPostCntTCP = 0;
char ErrSocket[] = "Error in socket";
char ErrSendTo[] = "Error in sendto";
char ErrRecvFrom[] = "Error in recvfrom";
int udpsock, rawsock, tcpsock, retval, iplen, UDPcount, TCPcount;
struct timeval mytimeout;
char UDPport[L65536*L6];
char UDPservice[L65536*L32], *UDPtptr;
char TCPport[L65536*L6];
char TCPservice[L65536*L32], *TCPtptr;
HPOINTER hIcon;
BOOL StopFlag = FALSE;
HINI hini;     // Handle to private INI file
ULONG DataLen;
char INIname[] = "PORTSCAN.INI";
HAB hab;  // Anchor
HMQ hmq;  // Message queue handle
char FormTime[L32];

//=============================================================================
// Main procedure
//=============================================================================
void main(int argc, char *argv[])
     {
     hab = WinInitialize (0);          // Anchor
     hmq = WinCreateMsgQueue(hab, 0);  // Message queue handle

     ac = argc;
     av = argv;

#ifdef TCPV40HDRS    // Включить для TCP/IP 4.0
     sock_init();
#endif               // TCPV40HDRS

     WinDlgBox( HWND_DESKTOP, HWND_DESKTOP, DlgMenu, NULLHANDLE,
                DIALOGWIN, 0 );

     WinDestroyMsgQueue(hmq);
     WinTerminate(hab);
     }

//=============================================================================
// Dialog procedure
//=============================================================================
MRESULT EXPENTRY DlgMenu (HWND hwndDlg, ULONG msg, MPARAM mp1, MPARAM mp2)
  {
  ULONG PostTCP, PostUDP;
  static BOOL res;

  switch (msg)
    {
//-----------------------------------------------------------------------------
// Handle the initialization of the dialog
//-----------------------------------------------------------------------------
    case WM_INITDLG:
      {
      long ColorWhite = CLR_WHITE, ColorBlack = CLR_BLACK, ColorCyan = CLR_CYAN;
//-----------------------------------------------------------------------------
// Инициализация диалога
//-----------------------------------------------------------------------------
      if ( ac < 2 )
        {
        SendErrMsg(hwndDlg,
                   "Syntax: PortScan <IP_addr> [s_port [e_port [timeout]]]");
        break;
        }

      hIcon = (HPOINTER)WinLoadPointer(HWND_DESKTOP, NULLHANDLE, 1);
      WinSendMsg(hwndDlg, WM_SETICON, (MPARAM) hIcon, 0l);
      WinSendDlgItemMsg(hwndDlg, PORT_S, EM_SETTEXTLIMIT, (MPARAM)L5, 0);
      WinSendDlgItemMsg(hwndDlg, PORT_P, EM_SETTEXTLIMIT, (MPARAM)L5, 0);
      WinSendDlgItemMsg(hwndDlg, TIMEOUT, EM_SETTEXTLIMIT, (MPARAM)L2, 0);

      myaddr_tcp = resolv(hwndDlg, av[1]);
      memcpy((char *)&myaddr_udp, (char *)&myaddr_tcp, sizeof(myaddr_tcp));
      memcpy((char *)&whereto, (char *)&myaddr_tcp, sizeof(myaddr_tcp));
      sprintf(titleaddr+strlen(titleaddr),"%s",inet_ntoa(myaddr_udp.sin_addr));
      WinSetDlgItemText(hwndDlg, IP_ADDRESS, titleaddr);

      sprintf(SPini+1, "%s", inet_ntoa(myaddr_udp.sin_addr));
      strcpy(PPini+1, SPini+1);
      strcpy(TOini+1, SPini+1);
      hini = PrfOpenProfile(hab, INIname); // Open private profile
      if ( hini )
        {
        GetParm(START_PORT, start_port);   // Получим общие параметры
        GetParm(STOP_PORT, stop_port);
        GetParm(ICMP_TIMEOUT, icmp_timeout);

        GetParm(SPini, start_port); // Получим параметры для конкретного IP
        GetParm(PPini, stop_port);
        GetParm(TOini, icmp_timeout);
        PrfCloseProfile(hini);   // Close private profile
        }

      if ( ac > 2 ) sport = (unsigned short)atoi(av[2]);
      else sport = start_port;
      if ( ac > 3 ) eport = (unsigned short)atoi(av[3]);
      else eport = stop_port;
      if ( ac > 4 ) timeout = (unsigned short)atoi(av[4]);
      else timeout = icmp_timeout;

      TestParm(hwndDlg);
      sprintf(MsgText, "%d", sport);
      WinSetDlgItemText(hwndDlg, PORT_S, MsgText);
      sprintf(MsgText, "%d", eport);
      WinSetDlgItemText(hwndDlg, PORT_P, MsgText);

      mytimeout.tv_sec = timeout;
      mytimeout.tv_usec = L0;
      sprintf(MsgText, "%d", timeout);
      WinSetDlgItemText(hwndDlg, TIMEOUT, MsgText);

      InitContainerTCP(hwndDlg);
      WinSetPresParam( WinWindowFromID(hwndDlg, CONT_TCP),
                       PP_BACKGROUNDCOLORINDEX, sizeof(long),
                       (PVOID)&ColorWhite );
      WinSetPresParam( WinWindowFromID(hwndDlg, CONT_TCP),
                       PP_FOREGROUNDCOLORINDEX, sizeof(long),
                       (PVOID)&ColorBlack );
      WinSetPresParam( WinWindowFromID(hwndDlg, CONT_TCP),
                       PP_HILITEBACKGROUNDCOLORINDEX, sizeof(long),
                       (PVOID)&ColorCyan );
      WinSetPresParam( WinWindowFromID(hwndDlg, CONT_TCP),
                       PP_HILITEFOREGROUNDCOLORINDEX, sizeof(long),
                       (PVOID)&ColorBlack );

      InitContainerUDP(hwndDlg);
      WinSetPresParam( WinWindowFromID(hwndDlg, CONT_UDP),
                       PP_BACKGROUNDCOLORINDEX, sizeof(long),
                       (PVOID)&ColorWhite );
      WinSetPresParam( WinWindowFromID(hwndDlg, CONT_UDP),
                       PP_FOREGROUNDCOLORINDEX, sizeof(long),
                       (PVOID)&ColorBlack );
      WinSetPresParam( WinWindowFromID(hwndDlg, CONT_UDP),
                       PP_HILITEBACKGROUNDCOLORINDEX, sizeof(long),
                       (PVOID)&ColorCyan );
      WinSetPresParam( WinWindowFromID(hwndDlg, CONT_UDP),
                       PP_HILITEFOREGROUNDCOLORINDEX, sizeof(long),
                       (PVOID)&ColorBlack );
//-----------------------------------------------------------------------------
// Create Semaphor and Threads, Set Priority
//-----------------------------------------------------------------------------
      DosSetPriority(PRTYS_THREAD, PRTYC_REGULAR, L16, L0);

      res = PingTest(hwndDlg);
      if ( !res ) SendWngMsg(hwndDlg, "Unsuccessful PING");

      WinEnableControl(hwndDlg, PB_RUN, !res);
      WinEnableControl(hwndDlg, PB_SAVE, !res);
      WinEnableControl(hwndDlg, PB_LOG, !res);
      WinEnableControl(hwndDlg, PB_STOP, res);

      DosCreateEventSem( (ULONG)NULL, &hevEventHandleUDP,
                         DC_SEM_SHARED, res );
      DosCreateEventSem( (ULONG)NULL, &hevEventHandleTCP,
                         DC_SEM_SHARED, res );

      DosCreateThread( &tidUDP,
                       (PFNTHREAD) DoScanUDP,
                       hwndDlg,
                       CREATE_READY | STACK_SPARSE,
                       L65536 );
      DosCreateThread( &tidTCP,
                       (PFNTHREAD) DoScanTCP,
                       hwndDlg,
                       CREATE_READY | STACK_SPARSE,
                       L65536 );
      break;
      }

//-----------------------------------------------------------------------------
// Ошибка при сканировании
//-----------------------------------------------------------------------------
    case WM_USER_SCAN_ERROR:
      {
      SendErrMsg(hwndDlg, ErrMsg);
      break;
      }

//-----------------------------------------------------------------------------
// Выполняем сканирование порта UDP
//-----------------------------------------------------------------------------
    case WM_USER_UDP_LINE:
      {
      sprintf(UDPtext,"Port %d", SHORT1FROMMP(mp1));
      WinSetDlgItemText(hwndDlg, MSG_UDP, UDPtext);
      break;
      }

//-----------------------------------------------------------------------------
// Выполняем сканирование порта TCP
//-----------------------------------------------------------------------------
    case WM_USER_TCP_LINE:
      {
      sprintf(TCPtext,"Port %d", SHORT1FROMMP(mp1));
      WinSetDlgItemText(hwndDlg, MSG_TCP, TCPtext);
      break;
      }

//-----------------------------------------------------------------------------
// Сканирование портов UDP завершено
//-----------------------------------------------------------------------------
    case WM_USER_SCAN_UDP_DONE:
      {
      WinSetDlgItemText(hwndDlg, MSG_UDP, "");

      DosQueryEventSem( hevEventHandleTCP, &PostTCP );
      WinEnableControl(hwndDlg, PB_STOP, PostTCP != 0);
      WinEnableControl(hwndDlg, PB_RUN, PostTCP == 0);
      WinEnableControl(hwndDlg, PB_LOG, PostTCP == 0);
      WinEnableControl(hwndDlg, PB_SAVE, PostTCP == 0);
      break;
      }

//-----------------------------------------------------------------------------
// Сканирование портов TCP завершено
//-----------------------------------------------------------------------------
    case WM_USER_SCAN_TCP_DONE:
      {
      WinSetDlgItemText(hwndDlg, MSG_TCP, "");

      DosQueryEventSem( hevEventHandleUDP, &PostUDP );
      WinEnableControl(hwndDlg, PB_STOP, PostUDP != 0);
      WinEnableControl(hwndDlg, PB_RUN, PostUDP == 0);
      WinEnableControl(hwndDlg, PB_LOG, PostUDP == 0);
      WinEnableControl(hwndDlg, PB_SAVE, PostUDP == 0);
      break;
      }

//-----------------------------------------------------------------------------
// Добавим запись о порте UDP
//-----------------------------------------------------------------------------
    case WM_USER_UDP_LINE_DONE:
      {
      InsertRecordUDP( hwndDlg, LONGFROMMP(mp1) );
      break;
      }

//-----------------------------------------------------------------------------
// Добавим запись о порте TCP
//-----------------------------------------------------------------------------
    case WM_USER_TCP_LINE_DONE:
      {
      InsertRecordTCP( hwndDlg, LONGFROMMP(mp1) );
      break;
      }

//-----------------------------------------------------------------------------
// Handle WM_COMMAND
//-----------------------------------------------------------------------------
    case WM_COMMAND:
      {
      switch(SHORT1FROMMP(mp1))
        {
//-----------------------------------------------------------------------------
// Close the dialog
//-----------------------------------------------------------------------------
        case PB_EXIT:
          {
          WinSendMsg(hwndDlg, WM_CLOSE, 0L, 0L);
          break;
          }
//-----------------------------------------------------------------------------
// Остановим сканирование
//-----------------------------------------------------------------------------
        case PB_STOP:
          {
          StopFlag = TRUE;
          return(0);
          }

//-----------------------------------------------------------------------------
// Запишем Log
//-----------------------------------------------------------------------------
        case PB_LOG:
          {
          int i;
          FILE *LogFile;
          char temp[6];

          memset(temp, ' ', sizeof(temp));
          temp[5] = '\0';

          LogFile = fopen("PortScan.Log", "a");
          fprintf(LogFile, "%s started at %s on %s\n",
                  Title, FormTime, titleaddr);

          fprintf(LogFile, "TCP Port   Service\n");
          for (i=0; i<TCPcount; i++)
            {
            strcpy(temp+5-strlen(TCPport+L6*i), TCPport+L6*i);
            fprintf(LogFile, " %s     %s\n", temp, TCPservice+L32*i);
            }

          fprintf(LogFile, "UDP Port   Service\n");
          for (i=0; i<UDPcount; i++)
            {
            strcpy(temp+5-strlen(UDPport+L6*i), UDPport+L6*i);
            fprintf(LogFile, " %s     %s\n", temp, UDPservice+L32*i);
            }

          fclose(LogFile);
          return(0);
          }

//-----------------------------------------------------------------------------
// Сформируем INI-файл
//-----------------------------------------------------------------------------
        case PB_SAVE:
          {
          char InText[L6];
          int rc;

          WinQueryDlgItemText(hwndDlg, PORT_S, sizeof(InText), InText);
          sport = (unsigned short)atoi(InText);
          WinQueryDlgItemText(hwndDlg, PORT_P, sizeof(InText), InText);
          eport = (unsigned short)atoi(InText);
          WinQueryDlgItemText(hwndDlg, TIMEOUT, sizeof(InText), InText);
          timeout = (unsigned short)atoi(InText);

          TestParm(hwndDlg);
          sprintf(MsgText, "%d", sport);
          WinSetDlgItemText(hwndDlg, PORT_S, MsgText);
          sprintf(MsgText, "%d", eport);
          WinSetDlgItemText(hwndDlg, PORT_P, MsgText);

          mytimeout.tv_sec = timeout;
          mytimeout.tv_usec = L0;
          sprintf(MsgText, "%d", timeout);
          WinSetDlgItemText(hwndDlg, TIMEOUT, MsgText);

          rc = WinDlgBox( HWND_DESKTOP, hwndDlg, WinDefDlgProc,
                          NULLHANDLE, PROMPT_ID, NULL );
          hini = PrfOpenProfile(hab, INIname); // Open private profile
          if ( rc == DID_SPECIAL )
            {
            PrfWriteProfileData(hini, APPNAME, SPini, &sport, sizeof(sport));
            PrfWriteProfileData(hini, APPNAME, PPini, &eport, sizeof(eport));
            PrfWriteProfileData(hini,APPNAME,TOini,&timeout,sizeof(timeout));
            }
          if ( rc == DID_GENERAL )
            {
            PrfWriteProfileData(hini,APPNAME,START_PORT,&sport,sizeof(sport));
            PrfWriteProfileData(hini,APPNAME,STOP_PORT,&eport,sizeof(eport));
            PrfWriteProfileData( hini, APPNAME, ICMP_TIMEOUT,
                                 &timeout, sizeof(timeout) );
            }
          PrfCloseProfile(hini);   // Close private profile
          return(0);
          }

//-----------------------------------------------------------------------------
// Обработаем кнопку Run
//-----------------------------------------------------------------------------
        case PB_RUN:
          {
          char InText[L6];

          WinQueryDlgItemText(hwndDlg, PORT_S, sizeof(InText), InText);
          sport = (unsigned short)atoi(InText);
          WinQueryDlgItemText(hwndDlg, PORT_P, sizeof(InText), InText);
          eport = (unsigned short)atoi(InText);
          WinQueryDlgItemText(hwndDlg, TIMEOUT, sizeof(InText), InText);
          timeout = (unsigned short)atoi(InText);

          TestParm(hwndDlg);
          sprintf(MsgText, "%d", sport);
          WinSetDlgItemText(hwndDlg, PORT_S, MsgText);
          sprintf(MsgText, "%d", eport);
          WinSetDlgItemText(hwndDlg, PORT_P, MsgText);

          mytimeout.tv_sec = timeout;
          mytimeout.tv_usec = L0;
          sprintf(MsgText, "%d", timeout);
          WinSetDlgItemText(hwndDlg, TIMEOUT, MsgText);

          res = PingTest(hwndDlg);
          if ( !res ) SendWngMsg(hwndDlg, "Unsuccessful PING");

          WinEnableControl(hwndDlg, PB_RUN, !res);
          WinEnableControl(hwndDlg, PB_LOG, !res);
          WinEnableControl(hwndDlg, PB_SAVE, !res);
          WinEnableControl(hwndDlg, PB_STOP, res);

          if ( res )
            {
            StopFlag = FALSE;
            DosPostEventSem(hevEventHandleUDP);
            DosPostEventSem(hevEventHandleTCP);
            }
          return(0);
          }
//-----------------------------------------------------------------------------
        }
      }
    }
  return WinDefDlgProc(hwndDlg, msg, mp1, mp2);
  }

//=============================================================================
// PostErrMsg - подпрограмма информирования о наличии ошибки
//=============================================================================
void PostErrMsg(ULONG pHwnd, char *ptr)
{
   DosResetEventSem( hevEventHandleUDP, &ulPostCntUDP );
   DosResetEventSem( hevEventHandleTCP, &ulPostCntTCP );
   strcpy(ErrMsg, ptr);
   WinPostMsg( pHwnd, WM_USER_SCAN_ERROR, 0L, 0L );
   DosSuspendThread(tidUDP);
   DosSuspendThread(tidTCP);
}

//=============================================================================
// SendErrMsg - подпрограмма выдачи сообщений об ошибках
//=============================================================================
void SendErrMsg(HWND hwnd, char *ptr)
{
   WinMessageBox( HWND_DESKTOP,
                  hwnd,
                  ptr,
                  "PortScan Error",
                  0,
                  MB_OK | MB_APPLMODAL | MB_ERROR );
   WinPostMsg(hwnd, WM_CLOSE, 0L, 0L);
}

//=============================================================================
// SendWngMsg - подпрограмма выдачи сообщений об ошибках
//=============================================================================
void SendWngMsg(HWND hwnd, char *ptr)
{
   WinMessageBox( HWND_DESKTOP,
                  hwnd,
                  ptr,
                  "PortScan Warning",
                  0,
                  MB_OK | MB_APPLMODAL | MB_WARNING );
}

//-----------------------------------------------------------------------------
// Подпрограмма построения IP адреса
//-----------------------------------------------------------------------------
struct sockaddr_in resolv(HWND hwnd, char *address)
{
  struct sockaddr_in myaddr = { 0 };
  struct hostent *host;

  if ( (myaddr.sin_addr.s_addr = inet_addr(address)) == INADDR_NONE )
    {
    if ( (host = gethostbyname(address)) == NULL )
      {
      SendErrMsg(hwnd, "Invalid address");
      exit(0);
      }
    else memcpy(&myaddr.sin_addr, (int *)host->h_addr, host->h_length);
    }
  return myaddr;
}

//-----------------------------------------------------------------------------
// Подпрограмма проверки параметров
//-----------------------------------------------------------------------------
void TestParm(HWND hwnd)
{
  if ( sport > eport )
    {
    sport = SPORT;
    eport = EPORT;
    }

  if ( ( timeout == 0 ) | ( timeout > MAX_TIMEOUT ) )
    timeout = DEFAULT_TIMEOUT;
}

//=============================================================================
// InitContainerTCP - подпрограмма инициализации контейнера для TCP
//=============================================================================
void InitContainerTCP(HWND hwnd)
{
  static char pszCnrTitle[] = "TCP";
  static CNRINFO cnrinfo;
  static PFIELDINFO pFieldInfo, firstFieldInfo;
  static FIELDINFOINSERT fieldInfoInsert;
  static PFIELDINFOINSERT pFieldInfoInsert;
  static char pszColumnText1[]= "  Port  ";
  static char pszColumnText2[]= "Service";
  static u_long MsgFlg = CMA_FLWINDOWATTR | CMA_CNRTITLE;
  long NumCol = 2;

  cnrinfo.pszCnrTitle = pszCnrTitle;
  cnrinfo.flWindowAttr = CV_DETAIL | CA_CONTAINERTITLE |
                         CA_TITLESEPARATOR | CA_DETAILSVIEWTITLES;

  pFieldInfo=WinSendDlgItemMsg(hwnd, CONT_TCP, CM_ALLOCDETAILFIELDINFO,
                               MPFROMLONG(NumCol), NULL);
  firstFieldInfo = pFieldInfo;

  pFieldInfo->cb = sizeof(FIELDINFO);
  pFieldInfo->flData = CFA_STRING|CFA_HORZSEPARATOR|CFA_RIGHT|CFA_SEPARATOR;
  pFieldInfo->flTitle = CFA_CENTER;
  pFieldInfo->pTitleData = (PVOID) pszColumnText1;
  pFieldInfo->offStruct = FIELDOFFSET(USERRECORD_TCP,TCP_Port);
  pFieldInfo = pFieldInfo->pNextFieldInfo;

  pFieldInfo->cb = sizeof(FIELDINFO);
  pFieldInfo->flData = CFA_STRING | CFA_HORZSEPARATOR | CFA_LEFT;
  pFieldInfo->flTitle = CFA_LEFT;
  pFieldInfo->pTitleData = (PVOID) pszColumnText2;
  pFieldInfo->offStruct = FIELDOFFSET(USERRECORD_TCP,TCP_Service);

  cnrinfo.cFields = NumCol;
  fieldInfoInsert.cFieldInfoInsert = NumCol;

  fieldInfoInsert.cb = (ULONG)(sizeof(FIELDINFOINSERT));
  fieldInfoInsert.pFieldInfoOrder = (PFIELDINFO)CMA_FIRST;
  fieldInfoInsert.fInvalidateFieldInfo = TRUE;

  pFieldInfoInsert = &fieldInfoInsert;

  WinSendDlgItemMsg( hwnd,
                     CONT_TCP,
                     CM_INSERTDETAILFIELDINFO,
                     MPFROMP(firstFieldInfo),
                     MPFROMP(pFieldInfoInsert) );

  WinSendDlgItemMsg(hwnd,CONT_TCP,CM_SETCNRINFO,&cnrinfo,MPFROMLONG(MsgFlg));
}

//=============================================================================
// InitContainerUDP - подпрограмма инициализации контейнера для UDP
//=============================================================================
void InitContainerUDP(HWND hwnd)
{
  static char pszCnrTitle[] = "UDP";
  static CNRINFO cnrinfo;
  static PFIELDINFO pFieldInfo, firstFieldInfo;
  static FIELDINFOINSERT fieldInfoInsert;
  static PFIELDINFOINSERT pFieldInfoInsert;
  static char pszColumnText1[]= "  Port  ";
  static char pszColumnText2[]= "Service";
  static u_long MsgFlg = CMA_FLWINDOWATTR | CMA_CNRTITLE;
  long NumCol = 2;

  cnrinfo.pszCnrTitle = pszCnrTitle;
  cnrinfo.flWindowAttr = CV_DETAIL | CA_CONTAINERTITLE |
                         CA_TITLESEPARATOR | CA_DETAILSVIEWTITLES;

  pFieldInfo=WinSendDlgItemMsg( hwnd,
                                CONT_UDP,
                                CM_ALLOCDETAILFIELDINFO,
                                MPFROMLONG(NumCol),
                                NULL );
  firstFieldInfo = pFieldInfo;

  pFieldInfo->cb = sizeof(FIELDINFO);
  pFieldInfo->flData = CFA_STRING|CFA_HORZSEPARATOR|CFA_RIGHT|CFA_SEPARATOR;
  pFieldInfo->flTitle = CFA_CENTER;
  pFieldInfo->pTitleData = (PVOID) pszColumnText1;
  pFieldInfo->offStruct = FIELDOFFSET(USERRECORD_UDP,UDP_Port);
  pFieldInfo = pFieldInfo->pNextFieldInfo;

  pFieldInfo->cb = sizeof(FIELDINFO);
  pFieldInfo->flData = CFA_STRING | CFA_HORZSEPARATOR | CFA_LEFT;
  pFieldInfo->flTitle = CFA_LEFT;
  pFieldInfo->pTitleData = (PVOID) pszColumnText2;
  pFieldInfo->offStruct = FIELDOFFSET(USERRECORD_UDP,UDP_Service);

  cnrinfo.cFields = NumCol;
  fieldInfoInsert.cFieldInfoInsert = NumCol;

  fieldInfoInsert.cb = (ULONG)(sizeof(FIELDINFOINSERT));
  fieldInfoInsert.pFieldInfoOrder = (PFIELDINFO)CMA_FIRST;
  fieldInfoInsert.fInvalidateFieldInfo = TRUE;

  pFieldInfoInsert = &fieldInfoInsert;

  WinSendDlgItemMsg( hwnd,
                     CONT_UDP,
                     CM_INSERTDETAILFIELDINFO,
                     MPFROMP(firstFieldInfo),
                     MPFROMP(pFieldInfoInsert) );

  WinSendDlgItemMsg( hwnd,CONT_UDP,CM_SETCNRINFO,&cnrinfo,MPFROMLONG(MsgFlg));
}

//=============================================================================
// DoScanUDP - подпрограмма сканирования портов UDP
//=============================================================================
void APIENTRY DoScanUDP(ULONG parmHwnd)
{
unsigned short i;
fd_set r;
static char buff[] = "UDP port scan";
char recvbuff[MAXPACKET], *tptr;
struct icmp *packet;
struct ip *iphdr, *iporiginal;
struct tcphdr *tcph;
struct servent *service;
int err;

DosSetPriority(PRTYS_THREAD, PRTYC_REGULAR, L15, L0);

if ( (udpsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 )
  PostErrMsg(parmHwnd, ErrSocket);

myaddr_udp.sin_family = AF_INET;

for (;;)
   {
   DosWaitEventSem(hevEventHandleUDP, SEM_INDEFINITE_WAIT);

   UDPcount = 0;
   UDPtptr = UDPservice;

   WinPostMsg( WinWindowFromID(parmHwnd, CONT_UDP), // Очистим контейнер
               CM_REMOVERECORD, NULL,
               MPFROM2SHORT(L0, CMA_FREE | CMA_INVALIDATE) );

   for ( i=sport; i<=eport; i++ )
     {
     if ( StopFlag ) break;

     if ( (rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0 )
       PostErrMsg(parmHwnd, ErrSocket);
     FD_ZERO(&r);
     myFD_SET(rawsock, &r);

     WinPostMsg ( parmHwnd, WM_USER_UDP_LINE, MPFROMSHORT(i), 0 );

     myaddr_udp.sin_port = htons(i);

     if ( sendto(udpsock, buff, sizeof(buff), 0,
                 (struct sockaddr *)&myaddr_udp, sizeof(myaddr_udp)) < 0 )
       {
       err = sock_errno();
       if ( err == SOCEACCES ) // SOCEACCES - Permission denied (firewall)
         {
         soclose(rawsock);
         continue;
         }
       PostErrMsg(parmHwnd, ErrSendTo);
       }

     retval = select( rawsock+1, &r, NULL, NULL, &mytimeout );

     if ( retval > 0 )
       { // We got an answer lets check if its the one we want.
       memset(recvbuff, '\0', MAXPACKET);
       if ( (recvfrom(rawsock, recvbuff, MAXPACKET, 0, 0, 0)) < 0 )
         PostErrMsg(parmHwnd, ErrRecvFrom);

       soclose(rawsock);
//-----------------------------------------------------------------------------
// Problem with getting back the address of the host is that not all hosts
// will answer ICMP unreachable directly from thier own host.
//-----------------------------------------------------------------------------
       iphdr = (struct ip *)recvbuff;
       iplen = iphdr->ip_hl << 2;

       packet = (struct icmp *)(recvbuff + iplen);
       iporiginal = (struct ip *)&packet->icmp_data;

       tptr = (char *)iporiginal+(iporiginal->ip_hl << 2);
       tcph=(struct tcphdr *)tptr;

       if ( htons(tcph->th_dport) == i )
         {
         if ( (packet->icmp_type == ICMP_UNREACH) &&
              (packet->icmp_code == ICMP_UNREACH_PORT) ) continue;
         else
           {
           sprintf( ErrMsg,
                    "Port %d ICMP type=%d ICMP code=%d",
                    i, packet->icmp_type, packet->icmp_code );
           PostErrMsg(parmHwnd, ErrMsg);
           }
         }
       }
     else
       {
       *UDPtptr = '\0';
       if ( (service = getservbyport(htons(i), "udp")) != NULL )
         sprintf(UDPtptr, "%0.31s", service->s_name);
       sprintf(UDPport+L6*UDPcount, "%d", i);

       UDPtptr+=L32;
       WinPostMsg ( parmHwnd,
                    WM_USER_UDP_LINE_DONE,
                    MPFROMLONG(UDPcount++),
                    0 );
       soclose(rawsock);
       }
     }

   DosResetEventSem( hevEventHandleUDP, &ulPostCntUDP);
   WinPostMsg (parmHwnd, WM_USER_SCAN_UDP_DONE, 0L, 0L);
   }
}

//=============================================================================
// DoScanTCP - подпрограмма сканирования портов TCP
//=============================================================================
void APIENTRY DoScanTCP(ULONG parmHwnd)
{
unsigned short i;
struct servent *service;
int rc, err;
time_t ltime;
struct tm *timeptr;

DosSetPriority(PRTYS_THREAD, PRTYC_REGULAR, L15, L0);

for (;;)
   {
   DosWaitEventSem(hevEventHandleTCP, SEM_INDEFINITE_WAIT);

   TCPcount = 0;
   TCPtptr = TCPservice;

   WinPostMsg( WinWindowFromID(parmHwnd, CONT_TCP), // Очистим контейнер
               CM_REMOVERECORD, NULL,
               MPFROM2SHORT(L0, CMA_FREE | CMA_INVALIDATE) );

   time(&ltime);
   timeptr=localtime(&ltime);
   strftime(FormTime, sizeof(FormTime)-1, "%d/%m/%Y %T", timeptr);

   for ( i=sport; i<=eport; i++ )
     {
     WinPostMsg ( parmHwnd, WM_USER_TCP_LINE, MPFROMSHORT(i), 0 );

     if ( (tcpsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0 )
       PostErrMsg(parmHwnd, ErrSocket);

     myaddr_tcp.sin_family = AF_INET;
     myaddr_tcp.sin_port = htons(i);
     if ( (rc = connect(tcpsock, (struct sockaddr *)&myaddr_tcp,
                        sizeof(myaddr_tcp))) == 0 )
       {
       TCPtptr[0] = '\0';
       if ( (service = getservbyport(htons(i), "tcp")) != NULL )
         sprintf(TCPtptr, "%0.31s", service->s_name);
       sprintf(TCPport+L6*TCPcount, "%d", i);

       TCPtptr+=L32;
       WinPostMsg ( parmHwnd,
                    WM_USER_TCP_LINE_DONE,
                    MPFROMLONG(TCPcount++),
                    0 );

       }
     else
       {
       err = sock_errno();
// SOCETIMEDOUT - тайм-аут
// SOCECONNREFUSED - порт закрыт
// SOCEACCES - Permission denied (firewall)
       if ( (err != SOCECONNREFUSED) & (err != SOCETIMEDOUT) &
            (err != SOCEACCES) )
         {
         sprintf(ErrMsg, "Port %d sock_errno=%d", i, err);
         PostErrMsg(parmHwnd, ErrMsg);
         }
       }
     soclose(tcpsock);
     if ( StopFlag ) break;
     }

   DosResetEventSem( hevEventHandleTCP, &ulPostCntTCP );
   WinPostMsg (parmHwnd, WM_USER_SCAN_TCP_DONE, 0L, 0L);
   }
}

//=============================================================================
// InsertRecordUDP - подпрограмма добавления записи в контейнер UDP
//=============================================================================
void InsertRecordUDP(HWND hwnd, int i)
{
  ULONG  cbRecordData;
  static PUSERRECORD_UDP pUserRecord;
  static RECORDINSERT recordInsert;
  static char pszViewText[] = "Text View";
  static char pszViewIcon[] = "Icon View";
  static char pszViewName[] = "Name View";

  cbRecordData = (LONG) (sizeof(USERRECORD_UDP) - sizeof(RECORDCORE));
  pUserRecord = WinSendDlgItemMsg( hwnd,
                                   CONT_UDP,
                                   CM_ALLOCRECORD,
                                   MPFROMLONG(cbRecordData),
                                   MPFROMSHORT(L1) );

  pUserRecord->recordCore.cb       = sizeof(RECORDCORE);
  pUserRecord->recordCore.pszText  = pszViewText;
  pUserRecord->recordCore.pszIcon  = pszViewIcon;
  pUserRecord->recordCore.pszName  = pszViewName;
  pUserRecord->recordCore.hptrIcon = hIcon;

  pUserRecord->UDP_Port  = (PSZ)UDPport+L6*i;
  pUserRecord->UDP_Service = (PSZ)UDPservice+L32*i;

  recordInsert.cb                = sizeof(RECORDINSERT);
  recordInsert.pRecordParent     = NULL;
  recordInsert.pRecordOrder      = (PRECORDCORE)CMA_END;
  recordInsert.zOrder            = CMA_TOP;
  recordInsert.cRecordsInsert    = L1;
  recordInsert.fInvalidateRecord = TRUE;

  WinPostMsg( WinWindowFromID(hwnd, CONT_UDP),
              CM_INSERTRECORD,
              (PRECORDCORE)pUserRecord,
              &recordInsert );
}

//=============================================================================
// InsertRecordTCP - подпрограмма добавления записи в контейнер TCP
//=============================================================================
void InsertRecordTCP(HWND hwnd, int i)
{
  ULONG  cbRecordData;
  static PUSERRECORD_TCP pUserRecord;
  static RECORDINSERT recordInsert;
  static char pszViewText[] = "Text View";
  static char pszViewIcon[] = "Icon View";
  static char pszViewName[] = "Name View";

  cbRecordData = (LONG) (sizeof(USERRECORD_TCP) - sizeof(RECORDCORE));
  pUserRecord = WinSendDlgItemMsg( hwnd,
                                   CONT_TCP,
                                   CM_ALLOCRECORD,
                                   MPFROMLONG(cbRecordData),
                                   MPFROMSHORT(L1) );

  pUserRecord->recordCore.cb       = sizeof(RECORDCORE);
  pUserRecord->recordCore.pszText  = pszViewText;
  pUserRecord->recordCore.pszIcon  = pszViewIcon;
  pUserRecord->recordCore.pszName  = pszViewName;
  pUserRecord->recordCore.hptrIcon = hIcon;

  pUserRecord->TCP_Port  = (PSZ)TCPport+L6*i;
  pUserRecord->TCP_Service = (PSZ)TCPservice+L32*i;

  recordInsert.cb                = sizeof(RECORDINSERT);
  recordInsert.pRecordParent     = NULL;
  recordInsert.pRecordOrder      = (PRECORDCORE)CMA_END;
  recordInsert.zOrder            = CMA_TOP;
  recordInsert.cRecordsInsert    = L1;
  recordInsert.fInvalidateRecord = TRUE;

  WinPostMsg( WinWindowFromID(hwnd, CONT_TCP),
              CM_INSERTRECORD,
              (PRECORDCORE)pUserRecord,
              &recordInsert );
}
//=============================================================================
//	   I N _ C K S U M
// Checksum routine for Internet Protocol family headers (C Version)
//=============================================================================
u_short in_cksum(u_short* addr, int len)
{
   register int nleft = len;
   register u_short *w = addr;
   register int sum = 0;
   u_short answer = 0;

//-----------------------------------------------------------------------------
// Our algorithm is simple, using a 32 bit accumulator (sum),
// we add sequential 16 bit words to it, and at the end,
// fold back all the carry bits from the top 16 bits into the lower 16 bits.
//-----------------------------------------------------------------------------
   while( nleft > 1 )
      {
      sum += *w++;
      nleft -= 2;
      }

//-----------------------------------------------------------------------------
// mop up an odd byte, if necessary
//-----------------------------------------------------------------------------
   if ( nleft == 1 )
      {
      *(u_char *)(&answer) = *(u_char *)w ;
      sum += answer;
      }

//-----------------------------------------------------------------------------
// add back carry outs from top 16 bits to low 16 bits
//-----------------------------------------------------------------------------
   sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
   sum += (sum >> 16);                 // add possible carry
   answer = (u_short)~sum;             // ones complement & truncate to 16 bits
   return (answer);
}

//=============================================================================
// PingTest - подпрограмма проверки доступности узла IP
//=============================================================================
BOOL PingTest(HWND hwnd)
{
u_long len;
u_char outpack[MAXPACKET];
struct icmp *icp = (struct icmp *)outpack;
u_char *datap = (u_char *)(icp->icmp_data);
u_char inpack[MAXPACKET];
struct ip *ip = (struct ip *)inpack;
BOOL res;
int sock;
fd_set r;

   if ( (sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0 )
     PostErrMsg(hwnd, ErrSocket);

   whereto.sin_family = AF_INET;
   strcpy(icp->icmp_data, Title);
   strcat(icp->icmp_data, " ABCDEFGHIJKLMNOPRSTUVWXYZ 0123456789 Testing");
   len = strlen(icp->icmp_data) + 1 + (datap-outpack);
   icp->icmp_type = ICMP_ECHO;
   icp->icmp_code = 0;
   icp->icmp_id = 0x3554; // identitier for outbound packet
   icp->icmp_seq = 1;     // sequence number for outbound packet

   icp->icmp_cksum = 0;
   icp->icmp_cksum = in_cksum( (u_short*)icp, len ); // Compute ICMP CheckSum

   FD_ZERO(&r);
   myFD_SET(sock, &r);

   if ( sendto(sock,
               (char *)outpack,
               len,
               0,
               (struct sockaddr *)&whereto,
               sizeof(struct sockaddr_in))==-1 ) PostErrMsg(hwnd,ErrSendTo);

   if ( select(sock+1, &r, NULL, NULL, &mytimeout) <= 0 )
     {
     res = FALSE;
     soclose(sock);
     return res;
     }

   if ( recvfrom(sock, inpack, MAXPACKET, 0, 0, 0) == -1) res = FALSE;
   else res = TRUE;

   soclose(sock);
   return res;
}
