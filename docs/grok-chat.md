## Menu

The menu bar gains a Grok menu, between Window and Help. File stays for opening a log. The key is not an About item.

- Connect Grok... opens the key sheet. The label becomes Grok connected when a key is stored, and the item stays enabled so the analyst can replace it.
- Forget key deletes the ciphertext. It is disabled until a key is stored.
- Show chat toggles the right-hand pane. The pane is hidden until a key is stored, then shown.

Connect Grok... is the only way in. The pane does not contain a second settings control. The sheet is a password field, Save, and Cancel. Forget stays on the menu so a key cannot be removed only from a pane that is itself hidden.

## UI

The studio stays as it is. A chat column opens on the right, same width as the case pane, after Connect Grok... succeeds.

- Header: Grok.
- Transcript: analyst questions, the SQL used, and the answer.
- Composer: one field and Ask.
- Empty state, no key: the pane is hidden. The Grok menu is the prompt.
- Empty state, key set: "Ask about this case."
- Key sheet, from the menu: password field, last four characters when a key is already set, Save, Cancel. Forget is the menu item.

The grid does not move. Ask does not change the editor until the analyst presses Run on a reply.
