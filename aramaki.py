#!/usr/bin/python -u

'''
Aramaki is just a grep wrapper to be used during manual security code reviews.

in a nutshell:

1- Reasoning:

    - Auditing codebases manually can be daunting
    - Usually one searches (greps) for dangerous APIs
    - Grep output is hard to manage efficiently
    - We want something small that works out of the box on most systems
    - No need to install anything else (ack, gui lib...)

2- Features:

    - This code snippet is vulnerable, flag it
    - This pattern only produces false positives, ignore it
    - I need to open this file in my fav editor
    - This file should be ignored
    - I got tired. I will continue the review later
    - Please, resume at the point I left

Questions/comments @olemoudi / ole@makensi.es / http://makensi.es

'''

EDITOR = '/usr/bin/gvim'

import sys
import re
import subprocess
import curses
import traceback
import pickle
import os.path

VERSION = '0.0.2alpha'
TITLE = 'aramaki - assisting tool for manual code review (v%s)' % VERSION

CONTEXT = 8

# Common patterns for webapp source code security auditing. 
# Probably still some interesting keywords are missing but these will get your
# hands started and generate a good balance of interesting snippets vs false positives.
JAVA = '|getParameter|getQueryString|getHeader|getRequestURI|getRequestURL|getCookies|getRequestedSessionID|getInputStream|getReader|getMethod|getProtocol|getServerName|getRemoteUser|getUserPrincipal|java\.io\.FileinputStream|java\.io\.FileOutputStream|java\.io\.FileReader|java\.io\.FileWriter|createStatement|\.execute\(|\.executeQuery\(|\.prepareStatement|PreparedStatement|getRuntime|runtime\.exec\(|sendRedirect|setStatus\(|addHeader\(|Socket\(|login-config|security-constraint|session-config|error-page|init-param'
ASPNET = '|Request\[|\.Params|\.QueryString|\.ServerVariables|\.Headers|\.Url|\.RawURL|\.UrlReferrer|\.Cookies|\.BinaryRead|\.HTTPMethod|\.Browser|\.UserAgent|\.AcceptTypes|\.UserLanguages|FileStream|StreamReader|StreamWriter|SqlCommand|SqlDataAdapter|OleDbCommand|SqlCeCommand|Process|ProcessStartInfo|Redirect\(|Status\(|StatusCode\(|AddHeader\(|AppendHeader\(|Transfer\(|httpCookies|sessionstate|compilation|customErrors|httpRunTime'
PHP = "|\$_GET|\$_POST|\$_REQUEST|\$HTTP_.*_VARS|\$_COOKIE|\$_FILES|REQUEST_METHOD|QUERY_STRING|REQUEST_URI|SERVER\[.?HTTP_|PHP_SELF|fopen|readfile|file\(|fpassthru|gzopen|gzfile|gzpassthru|readgzfile|copy|rename|rmdir|mkdir|unlink|file_.*_contents|parse_ini_file|include_?|require_?|virtual|_query|eval\(|call_user|create_function|exec\(|passthru|popen|proc_open|shell_exec|system\(|http_redirect|header|httpmessage::setresponsecode|httpmessage::setheaders|socket_|fsockopen|->prepare|->bind_param|->execute|_prepare|register_globals|safe_mode|mail\(|magic_quotes|allow_url_|display_errors|file_uploads|upload_tmp_dir|post_max_size|upload_max_filesize|preg_|ereg_"
CLIENTSIDE = "|\.location|document\.URL|addEventListener\(.?message|javascript:|location.hash|eval\(|domain=.?\*|; ?url=|innerHTML|localStorage|sessionStorage|documentURI|baseURI|\.referrer|document\.write\(|\.execScript\(|\.setInterval\(|\.setTimeout\("
CUSTOM = "|regex|enkrypt|encrypt|crypt|clave|password|passwd|pwd|login|key|cipher|md5|sha1|hash|digest|sign|firma|b64|echo|https?:|://|\w+@\w+|email|aHR0|%2e%2e"

PATTERNS = "braubrau298" + PHP + JAVA + ASPNET + CLIENTSIDE + CUSTOM

GREPCOMMAND = 'grep -HRnIE -C '+str(CONTEXT)+' --color=never --exclude=*.aramaki "' + PATTERNS + '" '

# hardcoded config params, I am lazy ok?
OUTPUT = 'grepoutput.aramaki'
STATE = 'state.aramaki'
FLAGGED_FILE = 'flagged.aramaki'
GREPSEP = '--'
FOOTERTEMP = '[%i/%i]'
FILETEMP = 'File: '
TRIMFLAG = ['', '', '        [...]        ']
WARNING = "[TRIM] "
CURRENTHIT = []
IGNORED_FILES = []
IGNORED_PATTERNS = []
FLAGGED = []

# graphic params
MAXCOLS = 150
TWIN_HEIGHT = 3
CWIN_HEIGHT = 4
SWIN_HEIGHT = 25 
SVPAD = 2
SHPAD = 7
MAXSOURCELINES = SWIN_HEIGHT - (SVPAD*2) - 1

# [['path/to/file.ext', '-999-', 'actual content']]
# lines such as "/foo/log-2012-12-12-4589-hour 16:42:11 GET" are a bitch
def processGrepFile(f, sep):
    '''
    builds slides array out of grep output
    '''
    pprint("[*] Building code snippets...", colors.GREEN)
    rawslides = []
    rawslide = []
    for line in f: 
        line = line.strip()
        if line == sep:
            rawslides.append(rawslide)
            rawslide = []
            continue
        rawslide.append(line)

    slides = []
    # guess filename from each line
    for r in rawslides:
        filepath_candidates = []
        newslide = []
        for rawline in r:
            match = re.search('(?P<filepath>^.*?/[^/?*:;\\{}]*?.?[^/?*:;\\{}]*?):\d+?:', rawline)
            if match:
                filepath_candidates.append(match.groupdict()['filepath'])

        filepath = min(filepath_candidates, key=len) 

        for again in r:
            line = again[len(filepath):]
            split = re.split('(:\d+?:|-\d+?-)', line, 1)
            newslide.append([filepath, split[1], split[2]])

        slides.append(newslide)

    return slides

def grepFiles(files, output):
    '''
    grep command wrapper
    '''
    # command injection present, please autopwn yourself %)
    pprint("[*] Running grep... ", colors.GREEN)
    pprint("[*] Grep exit code was %i" % subprocess.call(GREPCOMMAND + " " + files, stdout=output, stderr=sys.stderr, shell=True), colors.GREEN)

def printSlide(slide, win, footer, flagged=False):
    '''
    displays one slide in the curses window
    '''

    if len(slide) > MAXSOURCELINES:
        # code snippet from grep is too big for the screen, trim it
        newslide = []
        available = MAXSOURCELINES - 1
        hits = 0
        for l in slide:
            if re.search(':\d+:', l[1]):
                hits += 1

        besteffort = True
        if ((hits - 1) * CONTEXT) + (hits*2) < available:
            besteffort = False
        skippedfirstcontext = False
        current = 0
        while available > 1 and current < len(slide):
            if re.search(':\d+:', slide[current][1]):
                skippedfirstcontext = True
                newslide.append([slide[current][0], slide[current][1], slide[current][2]])
                if besteffort:
                    newslide.append(TRIMFLAG)
                    available -= 2
                else:
                    available -= 1
            else:
                if (not besteffort) and skippedfirstcontext:
                    newslide.append([slide[current][0], slide[current][1], slide[current][2]])
                    available -= 1
            current += 1

        all_ignored = printSlide(newslide, win, footer, flagged)

    else:
        # code snippet fits the screen
        global CURRENTHIT
        win.clear()
        CURRENTHIT = []
        # print filename
        win.move(SVPAD -1, SHPAD)
        win.addstr(FILETEMP)

        if len(slide[0][0]) + SHPAD + len(FILETEMP) > MAXCOLS:
            win.addstr('...'+slide[0][len(slide[0][0]) + SHPAD + len(FILETEMP) - MAXCOLS + 4:], curses.A_BOLD)
        else:
            win.addstr(slide[0][0], curses.A_BOLD)
        line_offset = SVPAD
        fix = 0
        all_ignored = True
        for line in slide:
            if len(line[2]) > MAXCOLS - (SHPAD*2 + 5 - len(WARNING)):
                number = WARNING + line[1] + ' '
                source = line[2][:MAXCOLS*3/4] + "..."
                fix = len(WARNING)
            else:
                number = line[1] + ' '
                source = line[2]
            win.move(SVPAD + line_offset, SHPAD - fix)
            if re.search(':\d+:', number):
                numberatt = curses.A_BOLD
                curses.init_pair(1, curses.COLOR_RED, -1)
                sourceatt = curses.color_pair(1)|curses.A_BOLD
                splitpatts = PATTERNS.split('|')
                foundpatt = None
                hitted = False
                for p in splitpatts:
                    if re.search(p, source):
                        if p in IGNORED_PATTERNS:
                            numberatt = sourceatt = 0
                        else:
                            hitted = True
                            all_ignored = False
                            CURRENTHIT.append(p)
                if hitted:
                    numberatt = curses.A_BOLD
                    sourceatt = curses.color_pair(1)|curses.A_BOLD
                
            else:
                numberatt = sourceatt = 0
            win.addstr(number, numberatt)
            try:
                win.addstr(source, sourceatt)
            except:
                # damn non-ascii
                win.addstr(repr(codeline), sourceatt)
            line_offset += 1
            fix = 0

        if flagged:
            win.addstr(SWIN_HEIGHT - 1, MAXCOLS - 20, footer, curses.color_pair(1)|curses.A_BOLD) 
        else:
            win.addstr(SWIN_HEIGHT - 1, MAXCOLS - 20, footer) 

    return all_ignored

def f5():
    '''
    refresh all windows
    '''
    printTitle(twin)
    printCommands(cwin, CURRENTHIT)
    stdscr.refresh()
    twin.refresh()
    swin.refresh()
    cwin.refresh()

def printTitle(win):
    win.clear()
    win.addstr(1, 1, TITLE)
    win.hline(2, 0, curses.ACS_HLINE, MAXCOLS)

def printCommands(win, patterns, flagged=False):
    win.clear()
    win.hline(0, 0, curses.ACS_HLINE, MAXCOLS)
    win.addstr(1, 8, "Next")
    win.addstr(" (j) ", curses.A_BOLD)
    win.addstr("| Previous")
    win.addstr(" (k) ", curses.A_BOLD)
    if not flagged:
        win.addstr("| Flag")
        win.addstr(" (f) ", curses.A_BOLD)
    else:
        win.addstr("| Flagged! ", curses.color_pair(1)|curses.A_BOLD)
    win.addstr("| Ignore file")
    win.addstr(" (i) ", curses.A_BOLD)
    win.addstr("| Open in Editor")
    win.addstr(" (e) ", curses.A_BOLD)
    win.addstr("| Quit")
    win.addstr(" (q) ", curses.A_BOLD)
    l = " "
    n = 0
    s = set()
    for p in patterns:
        if p not in s:
            l += " %s (%i) |" % (p, n)
            n += 1
            s.add(p)
    win.addstr(2, 8, "Ignore pattern:" + l[:-1])

def cleanCurses():
    '''
    leave terminal in a sane state
    '''
    curses.curs_set(1)
    curses.nocbreak()
    stdscr.keypad(0)
    curses.echo()
    curses.endwin()

def flagSlide(slide):
    f = open(FLAGGED_FILE, 'a+')
    for l in slide:
        f.write(l[0] + l[1] + l[2] + '\n')
    f.write('--\n')
    f.flush()
    f.close()

def saveState():
    global state
    state['current'] = current
    state['ignored_files'] = IGNORED_FILES
    state['ignored_patterns'] = IGNORED_PATTERNS
    state['flagged'] = FLAGGED
    f = open(STATE, 'w')
    pickle.dump(state, f)
    f.close()

def printBanner():

    s = '''
\t                                _    _ 
\t                                | |  (_)
\t  __ _ _ __ __ _ _ __ ___   __ _| | ___ 
\t / _` | '__/ _` | '_ ` _ \ / _` | |/ / |
\t| (_| | | | (_| | | | | | | (_| |   <| |
\t \__,_|_|  \__,_|_| |_| |_|\__,_|_|\_\_|
\t \t \t \t \tv%s

\t \t Assisting tool for manual source review
\t \t Martin Obiols - @olemoudi - http://makensi.es
''' % VERSION
    pprint(s, colors.HEADER)

def confirm(prompt=None, resp=False):
    """prompts for yes or no response from the user. Returns True for yes and
    False for no.

    'resp' should be set to the default value assumed by the caller when
    user simply types ENTER.
    """
    
    if prompt is None:
        prompt = 'Confirm'

    if resp:
        prompt = '%s [%s/%s]: ' % (prompt, 'Y', 'n')
    else:
        prompt = '%s [%s/%s]: ' % (prompt, 'y', 'N')
        
    while True:
        ans = raw_input(prompt)
        if not ans:
            return resp
        if ans not in ['y', 'Y', 'n', 'N']:
            print 'please enter y or n.'
            continue
        if ans == 'y' or ans == 'Y':
            return True
        if ans == 'n' or ans == 'N':
            return False

class colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'

def pprint(text, color):
    print ""
    print color + text + colors.ENDC,


if __name__ == '__main__':

    printBanner() 
    global state
    restore = False
    if os.path.exists(STATE):
        pprint("[*] State file found (%s)" % STATE, colors.YELLOW)
        print ""
        restore = confirm("[*] Would you like to restore previous state?", True)
        if restore:
            pprint("[*] State restored from file", colors.GREEN)
            f = open(STATE, 'r')
            state = pickle.load(f)
            IGNORED_FILES = state['ignored_files']
            IGNORED_PATTERNS = state['ignored_patterns']
            FLAGGED = state['flagged']
            f.close()

    if not restore:
        pprint("[*] Initial state", colors.GREEN) 
        state = { 'current' : 0,
                    'ignored_files' : [],
                    'ignored_patterns' : [],
                    }

    if not os.path.exists(OUTPUT):
        output = open(OUTPUT, 'w+')
        grepFiles(sys.argv[1], output)
        output.seek(0)
    else:
        pprint("[*] Grep file found (%s)" % OUTPUT, colors.YELLOW)
        pprint("[*] Skipping grep", colors.GREEN)
        output = open(OUTPUT, 'r')

    slides = processGrepFile(output, GREPSEP)

    try:
        # configure curses
        tb = None
        stdscr = curses.initscr() # main window
        curses.start_color() # enable colors
        curses.use_default_colors()
        curses.curs_set(0)
        curses.noecho() # hide pressed keys
        curses.cbreak() # read pressed keys without waiting for intro

        # create windows
        twin = curses.newwin(TWIN_HEIGHT, MAXCOLS, 0, 0)
        swin = curses.newwin(SWIN_HEIGHT, MAXCOLS, TWIN_HEIGHT, 0)
        cwin = curses.newwin(CWIN_HEIGHT, MAXCOLS, TWIN_HEIGHT + SWIN_HEIGHT, 0)
        
        # set title
        printTitle(twin)
        # print command bar
        printCommands(cwin, CURRENTHIT)

        f5()

        current = state['current']
        antiweary = 0
        back = False
        while 1:

            # avoid index out of range 
            if current >= len(slides):
                current = len(slides) - 1
            elif current < 0:
                current = 0

            # skip slide for ignored files
            while slides[current][0][0] in IGNORED_FILES and current < (len(slides) - 1):
                if back:
                    current -= 1
                else:
                    current += 1
            # print slide and see return value for slides where all patterns are ignored  
            if current in FLAGGED:
                all_ignored = printSlide(slides[current], swin, FOOTERTEMP % (current+1, len(slides)), True )
            else:
                all_ignored = printSlide(slides[current], swin, FOOTERTEMP % (current+1, len(slides)), False )
            f5()
            if all_ignored and current < (len(slides) - 1):
                if back:
                    current -= 1
                else:
                    current +=1
                continue
            # wait for command
            c = stdscr.getch()
            # go forward
            if c == ord('j') and current < (len(slides) - 1):
                back = False
                current += 1
            # go back
            elif c == ord('k') and current > 0:
                back = True
                current -= 1
            # ignore file
            elif c == ord('i'):
                back = False
                IGNORED_FILES.append(slides[current][0][0])
                current += 1
                if current >= len(slides):
                    current = len(slides) - 1
            # quit aramaki
            elif c == ord('q'):
                cleanCurses()
                saveState()
                sys.exit(1)
            # flag snippet (slide)
            elif c == ord('f'):
                flagSlide(slides[current])
                back = False
                FLAGGED.append(current)
                current +=1
            # mark pattern to be ignored
            elif 48 <= c <= 57:
                IGNORED_PATTERNS.append(CURRENTHIT[c - 48])
            elif c == ord('e'):
                subprocess.call(EDITOR + " " + slides[current][0][0], shell=True)
            f5()

            # pickle every now and then
            if antiweary % 10 == 0:
                saveState()

    except Exception as exc:
       tb = traceback.format_exc()
         
            
    finally:
        # finish gracefully
        cleanCurses()
        if tb:
            print tb




