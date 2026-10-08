# Hunts

A hunt is a saved query that shipped with the application. It is named, and it is filed under a MITRE tactic and technique, so you do not have to remember that 4720 is "a user account was created".

Open Hunts in the left pane. Choose the tactic, then the technique. A click loads the SQL into the editor. Read it before you run it. The statements are ordinary SQL, and you can change them.

The first set covers a successful logon, a network logon, a failed logon, explicit credentials, an account created, an account changed, special privileges, and one account. The last of those still contains the word `USER`. That is a placeholder. Replace it with the account you are following, then Run. If you leave it, the hunt looks for a user who is not in your log.

A hunt click also labels the next run. That matters in the next chapter. The trail can tell a hunt from a statement you typed.

Hunts are not a second database. They are a way to get a useful statement into the editor without starting from a blank page.
