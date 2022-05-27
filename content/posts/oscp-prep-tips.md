---
title: "My OSCP Preparation Tips"
date: 2022-05-25T12:32:02+01:00
draft: false
---

It’s almost a bit of a cliché after passing the OSCP to do a writeup about the journey it took to get there - but I’m embracing the cliché for two reasons:

- When I was preparing I encountered tips and suggestions in blog posts that had a huge impact on the rest of my preparation.
- Approaching the OSCP with experience as a Programmer/Software Engineer can result in slightly different prioritisation during preparation, and anecdotally it’s touched on in fewer guides because it’s not the common path.

This isn’t going to be a structured plan, and it won’t encapsulate everything I did to prepare. I just want to throw out there - at a high level - some of the more important lessons I learnt and resources I used.

### My experience before starting the course 

Just some context on what my experience level and preparation was prior to starting the PEN-200 course:
- I studied English Literature at university, learnt programming after graduating, and worked as a software engineer for around four years before moving into a security role.
- As a software engineer I spent the majority of the time working on a Rails app, Golang microservices, Angular frontend, and covered a fair bit of DevOps as well. I was pretty comfortable jumping into new frameworks or languages at this point.
- I got hooked on CTFs a couple of years into programming. By the time I started the PEN-200 course, I had probably done around 60-70 boxes on HackTheBox, worked through about 50% of the Burp Web Academy labs, and read through a couple of books, such as The Art of Exploitation by Jon Erikson and The Hacker Playbook 2 by Peter Kim.
- I hadn’t attempted any other certifications, but I did complete Tiberius’ ‘Windows Privilege Escalation for OSCP & Beyond!’ course, and Heath Adams ‘Practical Ethical Hacking’ course on Udemy. 

## Mindset/Methodology

### Awareness of Making Assumptions

The first lesson I want to touch on relates to assumptions - the ease with which we make them when working with technology (be it hacking or programming), and how detrimental they can be to achieving whatever our goal is. You don't have to have been hacking for long to be burnt by an assumption that you have made about the system infront of you. There are so many opportunities to make poor assumptions when trying to hack something - assuming your nmap scan was accurate, assuming you can't `su -` to root with a database password, assuming you can't get a reverse shell back because the first couple of ports you tried were blocked. I believe that a core part of improving at hacking is becoming as aware of your own assumptions as possible.

During my first programming job, I asked an experienced team member whether starting a new development project ever felt easy. He replied with an analogy, that he thought the process always felt like trying to make his way through a maze in the dark - fumbling at the walls to navigate. He went on to say that whilst you might never reach the point where you have enough clarity and foresight to move through the maze unimpeded, over time you do build up both a confidence and intuition about whether you've gone down a dead end. No analogy is perfect, but I like this one for hacking as well because it conveys the feeling of limited view that is easily experienced when you get stuck trying to tackle a machine. In this analogy, I see the unverified assumptions we make as a voice that ultimately ends up pulling us down dead ends, or causing us to miss new paths entirely.

Identifying when you are making an assumption is metacognition and it’s not always easy. For me, it required conscious effort - and a reminder at the top of one of my checklists - to try and evaluate if I had made any assumptions I hadn’t verified, as opposed to methodically testing each avenue. *Am I assuming my user doesn’t have write permissions to that directory? Am I assuming an exploit won’t work because this version isn’t listed as vulnerable?* As you do more boxes for practice, you’ll start to build up some intuition about what might be a rabbit hole and what might be a successful attack path - but you have to tread that line between following a hunch, and making a false assumption that loses you a lot of time, pretty carefully.

Your methodology and notes are the tool with which you keep your assumptions in check.

### Think about every box in the context of your methodology

Every single box that you complete or get stuck on when preparing for this exam is an opportunity to either improve your methodology, or gain confidence in it. This lesson honestly didn’t fully click with me until I had already done around 150 boxes and my exam was a couple of months away. It’s so easy to slip into the mindset that you need to be smashing out as many boxes as possible.

At the end of every box, ask yourself questions about the process you just went through, and then think about how you could alter your approach if you were to tackle the box again in order to make the process smoother. The outcomes of this questioning are what you want to use to improve your checklists - or if the lessons seem super niche, just keep a list of “lessons learnt” that you can read through in the future when you get stuck. The majority of these lessons are likely to relate to tunnel visioning on something:

- You’re trying to get a foothold on a box and you’ve found an LFI in a web application.
- You think you might be able to use it to leak some user credentials from config files and access the box.
- You can’t find anything obvious with a manual approach so you hop over to ffuf/wfuzz and try some LFI wordlists - in fact you keep trying many wordlists because nothing fruitful seems to be showing up.
- You realise, after a while of effort or using a hint, that you haven’t tested for RFI, and this route gives you a pretty easy shell on the box.

In retrospect the solution will seem obvious - but it’s easy to tunnel vision like this. The question you ask yourself afterwards is how can I improve my methodology so I reduce the likelihood I lose time like that in the future. In this example, you decide that it’s probably a good idea to check for RFI early on if you discover a potential place for it/LFI, because it’s relatively quick to check and it’s a higher impact finding that will probably gain you a foothold. And then, most importantly, you **incorporate this lesson into your notes or checklists**. Don’t trust yourself to remember your revised methodology in your head - things will slip through.  


## Resources

### Use multiple lab platforms but be aware of their differences

Generally speaking, the style of machines across HackTheBox, TryHackMe, Proving Grounds, and the PEN-200 practice labs, do differ - use all of them and get a feel for what their differences are. As I mentioned earlier, by the time I started my PEN-200 course, I had primarily been using HackTheBox. I think just before kicking off the PEN-200, I also took a dive into TryHackMe and did quite a few rooms there as well. You aren’t going to encounter a massive number of machines on HackTheBox that require brute forcing or password guessing, in comparison to the PEN-200 labs or Proving Grounds machines at least. Personally, I started out going through all of TJ Null's spreadsheet of OSCP-like boxes, but as I started to run out, I just started picking up anything. For me, all of the different flavours of CTF/lab machines were useful, because whilst they differed in style and realism, all of them offered the same thing - places to get stuck. Getting stuck and then unstuck is what provides the opportunity to try and improve the next time round.


### Solidify where you already might be strong

If I had to guess, I would imagine that a lot of programmers who turn towards security and the OSCP approach the web app security element of hacking with some confidence. You’ve got some knowledge of frameworks and architectural patterns, you’ve spent a bunch of time using dev tools and debugging, and of course if you gain access to it, you can read and understand the source code. The thing is, for me this led to a false sense of confidence. I thought it would make sense to focus on the less familiar aspects of hacking, such as binary exploitation, windows security, privilege escalation, and maybe brush up on AppSec a bit later because it wouldn’t take so long. But that didn’t really work. It didn’t work because whilst I was able to pick up the theoretical overview of the AppSec stuff quite quickly, I would still get stuck on initial footholds in CTFs because my practical application of the techniques was under practiced. I might identify an input vulnerable to SQL injection relatively quickly in an application, and then get stuck actually exploiting it for ages. Ultimately, I had a really shallow knowledge of actually exploiting these web vulnerabilities. The thing that made the difference for me here was Burp Web Academy. I saw it suggested a couple of times during my OSCP preparation but not enough in my opinion - it’s an incredible resource. I would recommend at a minimum going and completing all of the server-side exploit modules. After completing around 50% of the labs, I was able to handle web app’s in CTFs with so much more confidence.

### Tackling Windows Generally

Windows was hands-down my least confident area before starting the PEN-200. I hadn’t owned a Windows computer before I got into security - and at work I had always programmed on a Mac. If I had to give one suggestion to a career-changing programmer who wants to do the OSCP, it would be just get as comfortable with Windows as you can. I started using a Windows machine at home (for gaming reasons too!), started focussing specifically on Windows CTF boxes, and started reading more blog posts online about anything Windows security. I think broadly speaking most CTF platforms have more Linux boxes than Windows ones - I definitely felt like I started to run out of Windows boxes with Proving Grounds - but one place where there are plenty is the actual PEN-200 practice labs. When you get in there just start trying to smash everything and you’ll end up covering a large number of Windows machines and feeling a lot more confident about it. Like many others, I highly recommend Tiberius’ course on privilege escalation.
 
### Tackling AD

Active Directory was initially a bit of a scary surprise because it’s inclusion in the exam was announced halfway through my lab time. It came to be one of my favourite parts of the experience though. As with Windows in general, I tried to just throw myself into AD as much as I could. Reading https://zer1t0.gitlab.io/posts/attacking_ad/ was a huge help - although I already feel like I need to go through the whole thing again. A couple of weeks before my exam I saw somebody in the Offensive Security discord suggest going through the Active Directory 101 track on HackTheBox - this was an amazing suggestion. In the week running up to my exam, I worked through all 10 machines (walkthrough-assisted for the insane machines), and really focussed on consolidating my active directory cheat sheets. On a few of the machines, I re-exploited them whilst taking a different approach to enumeration (varying between PowerView, Bloodhound, Empire, and a manual approach) with the goal of having checklists that covered all of them. By the end of that HackTheBox track, I felt so much more comfortable with AD. I did also buy the TryHackMe Throwback lab after seeing it suggested in the Discord. It did provide some value as an environment in which I could practice pivoting around multiple machines in a domain, but I'm not sure I gained much doing this than I already had pivoting in the PEN-200 lab environment. If your lab time has run out and you still feel like pivoting is a weakness of yours, it might be worth considering. Otherwise I'm not sure it's worth the money.

### Buffer Overflows

I only really have one suggestion for improving at these and that’s to read The Art of Exploitation by Jon Erikson. If you already have programming experience, and you have enough time before your course starts, just get stuck into it. It covers more than is needed just to be able to complete basic stack-based overflows, but it’s incredibly rewarding to work through - it’s probably my favourite hacking book to date. For me, going through the exercises, writing small bits of code, compiling them, and then poking around at them with gdb, taught me the basics of binary exploitation better than many resources I've looked at since.

## Practice

### Track your boxes

In the last few months before my exam, I found it useful to mark when I had done a box, and what OS it was (or whether it was BOF/AD practice) on a whiteboard calendar. This meant that I could look back over the previous week and see if I had been focussing on one thing too much rather than getting a more even distribution of practice. I also used it to mark the days where I didn’t really complete anything, and also when I planned to do a practice exam.

![oscp-whiteboard](/oscp-whiteboard.jpg#center)

### Do the lab report

I initially didn’t plan on doing the lab report back when it was worth 5 points, but as I’ve mentioned, the exam changes were announced half way through my lab time, and with the lab report being worth 10 points (and being necessary in the event you can’t crack the AD set), it felt obvious to go back and do it. It took me way longer than I anticipated. Some of the exercises felt quite laborious, and formatting it with all the screenshots into something of a manageable size was quite painful. However, when I got to the report-writing stage of my actual exam, I was really glad I had taken the time to do the lab report. Having practiced writing up attack steps for the lab machines, I had a much clearer idea of what screenshots I needed to demonstrate my actions, and because I had struggled to get the right formatting for laying out screenshots and code sections, it wasn’t a massive overhead to have to work it all out doing my exam report. I did also genuinely learn more from doing the course exercises. When you first read through the PDF, it’s easy to skim over some of the sections that you think you already know, but doing the exercises often reveals details you might have missed - or just helps build muscle memory.

### Do a practice exam

The practice exam I did was a bit half-assed, but it was still very valuable. The main thing I wanted to use a practice run for was to get a more accurate sense of the timing. I started my practice run at the same time my actual exam was going to start, and gave myself 6 machines (3 AD, 2 Linux, 1 Windows) and just worked through them but only spending a max of 2 hours on each machine at a time. Your practice exam is never going to be perfect. You can’t really have the machines running simultaneously so there is always downtime switching between machines. You might not get the right ballpark difficulty across all the machines, relative to the exam. But in my experience, getting some sense of the 24-hour exam time is still worth it.

***

That’s it for the unsolicited tips and lessons learnt! Ended up being a bit wordy. The OSCP exam is a stressful experience, but as everyone else says, you do grow throughout the process of tackling it. It is rewarding. Good luck to anyone taking it, and just keep putting in the practice!