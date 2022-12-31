chris:789456123
john:november
dennis:12345678
cassie:12345678910

# Hashcat regex:

: = Do nothing.
l = Lowercase all letters.
u = Uppercase all letters.
c = Capitalize the first letter and lowercase others.
sXY = Replace all instances of {X} with {Y}. "ss$ = p@ssword -> p@$$word"
$! = Add the exclaimation character at the end.
'N = Truncate word at position N [index]. "'5 = password123 -> passw"
DN = Delete @ N. "D4 = Password123 -> Passord123"

```bash
bluechat@htb ~ $ cat custom.rule

:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! so0 sa@
$! c so0 sa@

```

## Generating Rule-based wordlists:

```bash
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_passwords.list

password
Password
passw0rd
Passw0rd
p@ssword
P@ssword
P@ssw0rd
password!
Password!
passw0rd!
p@ssword!
Passw0rd!
P@ssword!
p@ssw0rd!
P@ssw0rd!
```

Hashcat and John come with pre-built rule lists that we can use for our password generating and cracking purposes. One of the most used rules is `best64.rule`, which can often lead to good results. It's important to note that password cracking and the creation of custom wordlists is a guessing game in most cases.

We can narrow this down and perform more targeted guessing if we have information about the password policy and take into account the company name, geographical region, industry and other topics/words that users may select from to create their passwords. Exceptions are, of course, cases where passwords are leaked and found.

```bash
ls /usr/share/hashcat/rules/


best64.rule                  specific.rule
combinator.rule              T0XlC-insert_00-99_1950-2050_toprules_0_F.rule
d3ad0ne.rule                 T0XlC-insert_space_and_special_0_F.rule
dive.rule                    T0XlC-insert_top_100_passwords_1_G.rule
generated2.rule              T0XlC.rule
generated.rule               T0XlCv1.rule
hybrid                       toggles1.rule
Incisive-leetspeak.rule      toggles2.rule
InsidePro-HashManager.rule   toggles3.rule
InsidePro-PasswordsPro.rule  toggles4.rule
leetspeak.rule               toggles5.rule
oscommerce.rule              unix-ninja-leetspeak.rule
rockyou-30000.rule

```

## Generating Wordlists with CeWL:

```bash
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
```

-d = "depth"
-m = "minimum length"

[22][ssh] host: 10.129.202.64   login: sam   password: B@tm@n2022!
