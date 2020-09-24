/*
 * shell.C -- CEG433 File Sys Project shell
 * pmateti@wright.edu
 */

#include "fs33types.hpp"
#include "unistd.h"
#include <signal.h>
#include <iostream>
#include <string>
#include <sys/wait.h>

extern MountEntry *mtab;
extern VNIN cwdVNIN;
FileVolume * fv;                                // Suspicious!
Directory * wd;                                 // Suspicious!

#define nArgsMax 10
char types[1+nArgsMax];		// +1 for \0

/* An Arg-ument for one of our commands is either a "word" (a null
 * terminated string), or an unsigned integer.    We store both
 * representations of the argument. */

class Arg {
public:
    char *s;
    uint u;
} arg[nArgsMax];

uint nArgs = 0;

uint TODO()
{
    printf("to be done!\n");
    return 0;
}

uint TODO(char *p)
{
    printf("%s to be done!\n", p);
    return 0;
}

uint isDigit(char c)
{
    return '0' <= c && c <= '9';
}

uint isAlphaNumDot(char c)
{
    return c == '.' || 'a' <= c && c <= 'z'
            || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9';
}

int toNum(const char *p)
{
    return (p != 0 && '0' <= *p && *p <= '9' ? atoi(p) : 0);
}

SimDisk * mkSimDisk(byte *name)
{
    SimDisk * simDisk = new SimDisk(name, 0);
    if (simDisk->nSectorsPerDisk == 0) {
        printf("Failed to find/create simDisk named %s\n", name);
        delete simDisk;
        simDisk = 0;
    }
    return simDisk;
}

void doMakeDisk(Arg * a)
{
    SimDisk * simDisk = mkSimDisk((byte *) a[0].s);
    if (simDisk == 0)
        return;
    printf("new SimDisk(%s) = %p, nSectorsPerDisk=%d,"
	 "nBytesPerSector=%d, simDiskNum=%d)\n",
	 simDisk->name, (void*) simDisk, simDisk->nSectorsPerDisk,
	 simDisk->nBytesPerSector, simDisk->simDiskNum);
    delete simDisk;
}

void doWriteDisk(Arg * a)
{
    SimDisk * simDisk = mkSimDisk((byte *) a[0].s);
    if (simDisk == 0)
        return;
    char *st = a[2].s;		// arbitrary word
    if (st == 0)			// if it is NULL, we use ...
        st = "CEG433/633/Mateti";
    char buf[1024];		// assuming nBytesPerSectorMAX < 1024
    for (uint m = strlen(st), n = 0; n < 1024 - m; n += m)
        memcpy(buf + n, st, m);	// fill with several copies of st
    uint r = simDisk->writeSector(a[1].u, (byte *) buf);
    printf("write433disk(%d, %s...) == %d to Disk %s\n", a[1].u, st, r, a[0].s);
    delete simDisk;
}

void doReadDisk(Arg * a)
{
    SimDisk * simDisk = mkSimDisk((byte *) a[0].s);
    if (simDisk == 0)
        return;
    char buf[1024];		// assuming nBytesPerSectorMAX < 1024
    uint r = simDisk->readSector(a[1].u, (byte *) buf);
    buf[10] = 0;			// sentinel
    printf("read433disk(%d, %s...) = %d from Disk %s\n", a[1].u, buf, r, a[0].s);
    delete simDisk;
}

void doQuit(Arg * a)
{
    exit(0);
}

void doEcho(Arg * a)
{
    printf("%s#%d, %s#%d, %s#%d, %s#%d\n", a[0].s, a[0].u,
	 a[1].s, a[1].u, a[2].s, a[2].u, a[3].s, a[3].u);
}

void doMakeFV(Arg * a)
{
    SimDisk * simDisk = mkSimDisk((byte *) a[0].s);
    if (simDisk == 0)
        return;
    fv = simDisk->make33fv();
    printf("make33fv() = %p, Name == %s, Disk# == %d\n",
	 (void*) fv, a[0].s, simDisk->simDiskNum);

    if (fv) {
            wd = new Directory(fv, 1, 0);
            cwdVNIN = mkVNIN(simDisk->simDiskNum, 1);
    }
}

void doCopyTo(byte* from, byte* to)
{
    uint r = fv->write33file(to, from);
    printf("write33file(%s, %s) == %d\n", to, from, r);
}

void doCopyFrom(byte* from, byte* to)
{
    uint r = fv->read33file(to, from);
    printf("read33file(%s, %s) == %d\n", to, from, r);
}

void doCopy33(byte* from, byte* to)
{
    uint r = fv->copy33file(to, from);
    printf("copy33file(%s, %s) == %d\n", to, from, r);
}

void doCopy(Arg * a)
{
    byte* to = (byte *) a[0].s;
    byte* from = (byte *) a[1].s;

    if (a[0].s[0] == '@' && a[1].s[0] != '@') {
        doCopyTo(from, (to + 1));
    }
    else if (a[0].s[0] != '@' && a[1].s[0] == '@') {
        doCopyFrom((from + 1), to);
    }
    else if (a[0].s[0] != '@' && a[1].s[0] != '@') {
        doCopy33(from, to);
    }
    else {
        puts("Wrong arguments to cp.");
    }
}

void doLsLong(Arg * a)
{
    printf("\nDirectory listing for disk %s, cwdVNIN == 0x%0lx begins:\n",
	 wd->fv->simDisk->name, (ulong) cwdVNIN);
    wd->ls();                                         // Suspicious!
    printf("Directory listing ends.\n");
}

void doRm(Arg * a)
{
    uint in = wd->fv->deleteFile((byte *) a[0].s);
    printf("rm %s returns %d.\n", a[0].s, in);
}

void doInode(Arg * a)
{
    uint ni = a[0].u;

    wd->fv->inodes.show(ni);
}

void doMkDir(Arg * a)
{
    TODO("doMkDir");
}

void doChDir(Arg * a)
{
    TODO("doChDir");
}

void doPwd(Arg * a)
{
    TODO("doPwd");
}

void doMv(Arg * a)
{
    TODO("doMv");
}

void doMountDF(Arg * a)		// arg a ignored
{
    TODO("doMountDF");
}

void doMountUS(Arg * a)
{
    TODO("doMountUS");
}

void doUmount(Arg * a)
{
    TODO("doUmount");
}

void doCat(Arg *a) {
    system("cat");
}

/* The following describes one entry in our table of commands.    For
 * each cmmdName (a null terminated string), we specify the arguments
 * it requires by a sequence of letters.    The letter s stands for
 * "that argument should be a string", the letter u stands for "that
 * argument should be an unsigned int."    The data member (func) is a
 * pointer to the function in our code that implements that command.
 * globalsNeeded identifies whether we need a volume ("v"), a simdisk
 * ("d"), or a mount table ("m").    See invokeCmd() below for exact
 * details of how all these flags are interpreted.
 */

class CmdTable {
public:
    char *cmdName;
    char *argsRequired;
    char *globalsNeeded;		// need d==simDisk, v==cfv, m=mtab
    void (*func) (Arg * a);
} cmdTable[] = {
    {"cd", "s", "v", doChDir},
    {"cp", "ss", "v", doCopy},
    {"echo", "ssss", "", doEcho},
    {"inode", "u", "v", doInode},
    {"ls", "", "v", doLsLong},
    {"lslong", "", "v", doLsLong},
    {"mkdir", "s", "v", doMkDir},
    {"mkdisk", "s", "", doMakeDisk},
    {"mkfs", "s", "", doMakeFV},
    {"mount", "us","", doMountUS},
    {"mount", "", "", doMountDF},
    {"mv", "ss", "v", doMv},
    {"rddisk", "su", "", doReadDisk},
    {"rmdir", "s", "v", doRm},
    {"rm", "s", "v", doRm},
    {"pwd", "", "v", doPwd},
    {"q", "", "", doQuit},
    {"quit", "", "", doQuit},
    {"umount", "u", "m", doUmount},
    {"wrdisk", "sus", "", doWriteDisk},
    {"cat", "", "", doCat}
};

uint ncmds = sizeof(cmdTable) / sizeof(CmdTable);

void usage()
{
    printf("The shell has only the following cmds:\n");
    for (uint i = 0; i < ncmds; i++)
        printf("\t%s\t%s\n", cmdTable[i].cmdName, cmdTable[i].argsRequired);
    printf("Start with ! to invoke a Unix shell cmd\n");
}

/* pre:: k >= 0, arg[] are set already;; post:: Check that args are
 * ok, and the needed simDisk or cfv exists before invoking the
 * appropriate action. */

void invokeCmd(int k, Arg *arg)
{
    uint ok = 1;
    if (cmdTable[k].globalsNeeded[0] == 'v' && cwdVNIN == 0) {
        ok = 0;
        printf("Cmd %s needs the cfv to be != 0.\n", cmdTable[k].cmdName);
    }
    else if (cmdTable[k].globalsNeeded[0] == 'm' && mtab == 0) {
        ok = 0;
        printf("Cmd %s needs the mtab to be != 0.\n", cmdTable[k].cmdName);
    }

    char *req = cmdTable[k].argsRequired;
    uint na = strlen(req);
    for (uint i = 0; i < na; i++) {
        if (req[i] == 's' && (arg[i].s == 0 || arg[i].s[0] == 0)) {
            ok = 0;
            printf("arg #%d must be a non-empty string.\n", i);
        }
        if ((req[i] == 'u') && (arg[i].s == 0 || !isDigit(arg[i].s[0]))) {
	ok = 0;
	printf("arg #%d (%s) must be a number.\n", i, arg[i].s);
        }
    }

    if (ok)
        (*cmdTable[k].func) (arg);
}

/* pre:: buf[] is the command line as typed by the user, nMax + 1 ==
 * sizeof(types);; post:: Parse the line, and set types[], arg[].s and
 * arg[].u fields.
 */

void setArgsGiven(char *buf, Arg *arg, char *types, uint nMax)
{
    for (uint i = 0; i < nMax; i++) {
        arg[i].s = 0;
        types[i] = 0;
    }
    types[nMax] = 0;

    strtok(buf, " \t\n");		// terminates the cmd name with a \0

    for (uint i = 0; i < nMax;) {
            char *q = strtok(0, " \t");
            if (q == 0 || *q == 0) break;
            arg[i].s = q;
            arg[i].u = toNum(q);
            types[i] = isDigit(*q)? 'u' : 's';
            nArgs = ++i;
    }
}

/* pre:: name pts to the command token, argtypes[] is a string of
 * 's'/'u' indicating the types of arguments the user gave;; post::
 * Find the row number of the (possibly overloaded) cmd given in
 * name[].    Return this number if found; return -1 otherwise. */

int findCmd(char *name, char *argtypes)
{
    for (uint i = 0; i < ncmds; i++) {
        if (strcmp(name, cmdTable[i].cmdName) == 0 && strcmp(argtypes, cmdTable[i].argsRequired) == 0) {
            return i;
        }
    }
    return -1;
}

void ourgets(char *buf) {
    fgets(buf, 1024, stdin);
    char * p = index(buf, '\n');
    if (p) *p = 0;
}

int main() {
    char buf[1024];		// better not type longer than 1023 chars

    usage();
    for (;;) {
        *buf = 0;			// clear old input
        printf("%s", "sh33% ");	// prompt
        ourgets(buf);
        printf("cmd [%s]\n", buf);	// just print out what we got as-is
        if (buf[0] == 0)
            continue;
        if (buf[0] == '#')
            continue;			// this is a comment line, do nothing
        if (buf[0] == '!')		// begins with !, execute it as
            system(buf + 1);		// a normal shell cmd
        else {
            int output_file_handle = 0;
            int old_stdout = 10;
            int old_stdin = 11;

            // ##### START PIPE CODE ######
            // Look for a pipe
            bool use_pipe = false;
            for (int i = 0; i < 1024; i++)
                if (buf[i] == '|') {
                    use_pipe = true;
                    break;
                }

            // Set up pipe
            int pid;
            int *pipe_file_handles = new int[2];
            if (use_pipe) {
                // Parent will write to stdout, child will read
                // Create and set up pipe and fork
                int pipe_status = pipe(pipe_file_handles);
                pid = fork();

                // Set up read and write file handles for child/parent
                // Child
                if (pid == 0) {
                    // Get the command after the pipe
                    std::string buf_string = std::string(buf);
                    int pipe_index = buf_string.find('|');
                    buf_string = buf_string.substr(pipe_index + 1);
                    size_t p = buf_string.find_first_not_of(" \t");
                    buf_string.erase(0, p);
                    for (int i = 0; i < 1024; i++)
                        buf[i] = '\0';
                    for (int i = 0; i < buf_string.size(); i++)
                        buf[i] = buf_string[i];
                    dup2(STDIN_FILENO, old_stdin);  // Backup stdin
                    close(pipe_file_handles[1]);  // Close pipe output on child
                    dup2(pipe_file_handles[0], STDIN_FILENO);
                } else {
                    dup2(STDOUT_FILENO, old_stdout);  // Backup stdout
                    close(pipe_file_handles[0]);  // Close pipe input on parent
                    dup2(pipe_file_handles[1], STDOUT_FILENO);
                    // Get the command before the pipe
                    for (int i = 1023; i >= 0; i--) {
                        if (buf[i] == '|') {
                            for (int j = i - 1; j >= 0; j--)
                                if (!isAlphaNumDot(buf[j]))
                                    buf[j] = '\0';
                            buf[i] = '\0';
                            break;
                        }
                        buf[i] = '\0';
                    }
                }
            }
            // ##### STOP PIPE CODE ######

            // ##### START REDIRECT CODE ######
            // Iterate through the buffer looking for '>'
            // If found, redirect to file instead of outputting to stdout
            bool redirect = false;
            char filename[1024];
            int filename_index = 0;
            strcpy(filename, "");
            for (int i = 0; i < 1024; i++) {
                if (redirect) {
                    if (buf[i] != ' ') {
                    filename[filename_index] = buf[i];
                    filename_index++;
                    }
                }
                if (buf[i] == '>')
                    redirect = true;
            }

            // Get the filename and set the output redirect
            if (redirect) {
                int output_file_handle = open(filename, O_RDWR|O_CREAT, S_IRWXU);
                old_stdout = dup(STDOUT_FILENO);
                dup2(output_file_handle, STDOUT_FILENO);
            }
            // ##### STOP REDIRECT CODE ######

            // Figure out args
            setArgsGiven(buf, arg, types, nArgsMax);
            // Clear "ss" from the end of argtypes to get findCmd to still recognize the command
            if (redirect)
                for (int i = nArgsMax; i >= 0; i--)
                    if (types[i] == 's')
                        types[i] = '\0';

            // Find the command to run, and execute
            int k = findCmd(buf, types);
            if (k >= 0) {
                invokeCmd(k, arg);
                // Reset stdin/out
                if (redirect)
                    dup2(old_stdout, STDOUT_FILENO);
                if (use_pipe) {
                    if (pid == 0) {
                        close(pipe_file_handles[0]);
                        dup2(old_stdin, STDIN_FILENO);
                        exit(0);
                    } else {
                        close(pipe_file_handles[1]);
                        dup2(old_stdout, STDOUT_FILENO);
                        wait(NULL);
                    }
                }
            } else {
                // Reset stdin/out
                if (redirect)
                    dup2(old_stdout, STDOUT_FILENO);
                if (use_pipe) {
                    if (pid == 0) {
                        dup2(old_stdin, STDIN_FILENO);
                        exit(0);
                    } else {
                        dup2(old_stdout, STDOUT_FILENO);
                        wait(NULL);
                    }
                }
                usage();
            }
        }
    }
}

// -eof-

