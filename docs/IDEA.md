# Frank FBI

This is going to be a software to scan e-mails and score them from 100% fraud/spam to 100% trustworthy (of course, 100% is impossible, but just to understand the range).

I need you to do a deep thorough research on all the most recent and well known techniques to score fraudulent emails. Research if there are open databases we can rely on to cross information. Research if there are good free antivirus (virustotal) to scan links and attachments.

I have a directory "suspects" with a sample of good and bad emails that we will use to test all techniques.

I want to have a report with scores in several scanning layers until you arrive with a final score and final conclusion. It's important to not just give a number, but explain what made the mails succeed or fail a layer.

If you don't have enough information, it's best to say: "we don't have enough information, but it feels like good/bad because ..". the important part is the explanation.

I want this to be a Rails 8, headless application, mainly with activejobs and actionmailer to fetch from a gmail account I will create. The use case is that I will receive suspectious emails and I will forward them to this email. You will make the scanning and processing, formulate a pretty, light and easy to read report, and reply back on each thread.

I want you to also use ruby-llm, the most recent version (research api online), and allow me to configure openrouter keys and use grok, claude and gpt (let's do 3 parallel consultations to cross information). So you will do algorithms to deterministically extract key data points from the email, score what can be scored by tools alone (for example, whois on the domain, antivirus, etc). Given the data we gather, you will formulate prompts that can do final analysis on all of them and come up with a verdict. Think what would be good when we have 3 AIs coming up with conclusions and justifications. So the final email is not too big to read. If it's too big, no user will read it.

You will also record the email and extracted data (and research you did online on spam databases, etc), so if someone forward the same kind of email, you already have extra data to use (let's rely on our local database a a source of investigation for future emails, think of that, of what makes sense to store and to query later). The more clean data we can store, that can improve our work in the future, the better. use sqlite3 for local storage. Encrypt critical information such as the person who forwarded the email and asked for the analysis (privacy).

Also encrypt emails you have high confidence were not spam/fraud. We don't care about scammers privacy, only real people.

Use best rails practices, security concerns, proper conventions, test all features, be careful to not make brittle code, or brittle tests, robustness and reliability are the most important things in a security app like this. I think I will self-host this in my docker home server, so make this as easy as possible to docker compose, and have external volumes to store emails/database, etc.
