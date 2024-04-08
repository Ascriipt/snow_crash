# **snow-crash**
### an introduction to the wonderful world of ✨cybersecurity✨

### level00 :
ok so, first of, what do we have to work with ?

```
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
```
----r--r-- 1 flag00  flag00      15 Mar  5  2016 john
----r--r--  1 flag00  flag00      15 Mar  5  2016 john
```
Alright, well, that was easy enough ! now let's see if we can read it.
```
$> whereis john
john: /usr/sbin/john
```
```
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
```
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
and well, fuck you for that.
`f2av5il02puano7naaf6adaaf`

# level02 :
```
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
