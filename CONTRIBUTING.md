## Contributor License Agreement ##

Patches and contributions are welcome. Before we can accept them, though, we
have to see to the legal details.

Contributions to any Google project must be accompanied by a Contributor
License Agreement. This is not a copyright **assignment**, it simply gives
Google permission to use and redistribute your contributions as part of the
project.

  * If you are an individual writing original source code and you're sure you
    own the intellectual property, then you'll need to sign an [individual
    CLA][].

  * If you work for a company that wants to allow you to contribute your work,
    then you'll need to sign a [corporate CLA][].

You generally only need to submit a CLA once, so if you've already submitted
one (even if it was for a different project), you probably don't need to do it
again.

[individual CLA]: https://developers.google.com/open-source/cla/individual
[corporate CLA]: https://developers.google.com/open-source/cla/corporate


## Submitting a patch ##

  1. If you are submitting a signature for one or more Wifi client devices,
     we require pcaps to be submitted along with the text signature.
     These are added in testdata/pcaps. The filename format is:
     "testdata/pcaps/Genus Species (2.4|5)Ghz any-arbitrary-text.pcap"

     The Genus and Species label added in the signature database needs
     to match the initial part of the filename, or (if there is a good
     reason not to) the specific file can be added in pcaptest.py.

     You should edit the pcap to contain just the Probe Request and
     Association Request packets, not a giant file of unrelated packets.
     It is encouraged for one CL to include multiple signatures and pcap
     files. Almost all devices have a different signature on 2.4GHz and on
     5 GHz networks. Additionally, many devices send different Probe and
     Association Requests when sending to the Broadcast SSID than to a
     specific SSID. Capturing one of each is encouraged. Many of the
     existing files in testdata/pcaps contain "Broadcast Probe" and
     "Specific Probe" variants for this reason.

  1. Follow the normal process of [forking][] the project, and setup a new
     branch to work in.  It's important that each group of changes be done in
     separate branches in order to ensure that a pull request only includes the
     commits related to that bug or feature.

  1. Any significant changes should almost always be accompanied by tests. The
     project already has good test coverage, so look at some of the existing
     tests (in the `vroom/` directory) if you're unsure how to go about it.

  1. Do your best to have [well-formed commit messages][] for each change.
     This provides consistency throughout the project, and ensures that commit
     messages are able to be formatted properly by various git tools.

  1. Finally, push the commits to your fork and submit a [pull request][].

[forking]: https://help.github.com/articles/fork-a-repo
[well-formed commit messages]: http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html
[pull request]: https://help.github.com/articles/creating-a-pull-request
