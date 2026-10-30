# EmailZit: mail marked as spam by Rspamd goes to Junk.
require ["fileinto", "mailbox"];
if anyof (header :contains "X-Spam" "Yes", header :contains "X-Spam-Status" "Yes") {
  fileinto :create "Junk";
  stop;
}
