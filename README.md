TornScope - Torn travel & status watcher
Website: https://app.tornscope.com

WHAT IT DOES
TornScope adds a small overlay on torn.com that watches the players you choose
(your "targets") and tells you what they are doing:

 - Travelling (with the destination and an estimated landing time), abroad,
   in hospital, in jail, okay.
 - An alarm when a target is about to land or comes back, so you can act
   at the right moment. Clicking the "Open Travel" link stops the alarm and opens
   Torn's travel page in the same tab.
 - A history of the flights seen (one record per flight, with destination,
   take-off and landing times).
 - A Premium status chip and a button that opens your TornScope dashboard
   (statistics, full history, targets management).

The overlay works on desktop (Tampermonkey) and in Torn PDA.

HOW TO INSTALL
 1. Install a userscript manager: Tampermonkey (https://www.tampermonkey.net)
    or use the built-in userscripts of Torn PDA.
 2. Install the script from this page.
 3. Open torn.com. The TornScope overlay appears. Enter your Torn API key in
    the overlay (a "Limited access" key is enough), then link your account.
 4. To create a TornScope account you need an invitation link from the owner.

TORN PDA
Torn PDA does not install scripts from a link. Copy the whole script and paste
it in Torn PDA > Settings > Userscripts > Add a new script.
Updates are not automatic there: paste the new version when one is released.

PRIVACY AND DATA (please read)
 - Your Torn API key stays in YOUR browser. It is only sent to api.torn.com.
   It is never sent to the TornScope server unless you explicitly enable an
   optional server-side feature, and then it is stored encrypted.
 - The script talks to two hosts only: api.torn.com and the TornScope server
   (app.tornscope.com / the TornScope Worker). Nothing else.
 - The TornScope server receives only the list of your targets and the
   status changes observed for them (state, destination, times).
 - Data of different accounts is never mixed.
 - The script reads no password, no chat, no private page content.
 - The code is not obfuscated: you can read everything before installing.

PREMIUM
Server-side tracking (watching your targets even when Torn is closed) is a
Premium feature. Beta testers get 2 weeks of free Premium.
Premium can be obtained by sending Xanax in-game to the owner with the
message "scope" (1 Xanax = 7 days; 14 days for members of the owner's faction
or company). See the Premium page on the website for the details.

SUPPORT
Questions, bugs, suggestions: contact Zeussh [4268037] in Torn, or use the
website https://app.tornscope.com

TornScope is a fan-made tool and is not affiliated with or endorsed by Torn.
It only uses the official Torn API and respects its rate limits.
