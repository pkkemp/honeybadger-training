+++
author = "Hugo Authors"
title = "Thoughts on TLS Inspection"
date = "2019-11-20"
description = ""
tags = ["emoji"]
image = "artist.jpg"
+++

Forward proxy TLS inspection is harmful
<!--more-->

## 1. TLSi Violates the Principle of Least Privilege

The white paper (if you can call it that) I reference above makes note that Insider Threats could result in compromise of user data, and could itself become a target of attack.

The white paper goes on to state that enterprises that choose to implement this technology should ensure that they are following the principle of "least privilege"

The problem with this suggestion is that it is neither useful nor honest. How can an enterprise ever hope to implement the principle of least privilege while purposefully injecting massive amounts of it in an unnecessary way? How can you prevent user data from being compromised in transit while breaking the very thing that is meant to provide that protection (TLS).

The `[emojify](https://gohugo.io/functions/emojify/)` function can be called directly in templates or [Inline Shortcodes](https://gohugo.io/templates/shortcode-templates/#inline-shortcodes).

To enable emoji globally, set `enableEmoji` to `true` in your site’s [configuration](https://gohugo.io/getting-started/configuration/) and then you can type emoji shorthand codes directly in content files; e.g.

<p><span class="nowrap"><span class="emojify">🙈</span> <code>:see_no_evil:</code></span>  <span class="nowrap"><span class="emojify">🙉</span> <code>:hear_no_evil:</code></span>  <span class="nowrap"><span class="emojify">🙊</span> <code>:speak_no_evil:</code></span></p>
<br>

The [Emoji cheat sheet](http://www.emoji-cheat-sheet.com/) is a useful reference for emoji shorthand codes.

***


## 2. TLSi complicates your attack surface

As an exercise for the security-conscious, consider the following:

1. What happens to data after its *only* protection is broken?
  1. Is it routed in plain-text through racks of equipment for further inspection? Who has access to those racks? What prevents someone from simply duplicating this traffic using something like an optical duplicator?
  2. What do those inspection devices do with user data?
2. Do you know what SSL/TLS library your TLSi device uses? Are you sure it doesn't contain



## 3. What are you *even* doing with it?

One of the things that no one seems to be able to answer when I ask is what exactly they hope to accomplish by breaking and inspecting TLS.

People often say things like:

- Protecting Intellectual Property
- Stopping malicious requests

These are valid goals, but no one seems to be able to explain the efficacy of this approach. Could these goals not be achieved in some other way that doesn't involve


## 4. TLSi only works on networks that you control

Why can't a user just download whatever data they need, go to Starbucks and upload it?


## 5. Do your users understand the risk they're at?

Do your users understand that you have access to their plain-text passwords, security questions, etc for things like their banking sites?

**N.B.** The above steps enable Unicode Standard emoji characters and sequences in Hugo, however the rendering of these glyphs depends on the browser and the platform. To style the emoji you can either use a third party emoji font or a font stack; e.g.


## 7. All Software has bugs

Another thing people never seem to think about is the fact that all software has bugs (vulnerabilities). Contrary to popular belief adding external software to a problem that stems from poor or insecure code is *unlikely* to make it better. In fact, it almost guarantees that you will introduce additional vulnerabilities or attack paths that you're probably not thinking about.


Below is a bug from iOS 7 (famously referred to as #gotofail), the bug in question was part of the SSL library for iOS devices. The bug (line 12)

### sslKeyExchange.c

```C

if ((err = SSLFreeBuffer(&hashCtx)) != 0)
        goto fail;

    if ((err = ReadyHash(&SSLHashSHA1, &hashCtx)) != 0)
        goto fail;
    if ((err = SSLHashSHA1.update(&hashCtx, &clientRandom)) != 0)
        goto fail;
    if ((err = SSLHashSHA1.update(&hashCtx, &serverRandom)) != 0)
        goto fail;
    if ((err = SSLHashSHA1.update(&hashCtx, &signedParams)) != 0)
        goto fail;
        goto fail;
    if ((err = SSLHashSHA1.final(&hashCtx, &hashOut)) != 0)
        goto fail;

	err = sslRawVerify(ctx,
                       ctx->peerPubKey,
                       dataToSign,				/* plaintext */
                       dataToSignLen,			/* plaintext length */
                       signature,
                       signatureLen);
	if(err) {
		sslErrorLog("SSLDecodeSignedServerKeyExchange: sslRawVerify "
                    "returned %d\n", (int)err);
		goto fail;
	}

fail:
    SSLFreeBuffer(&signedHashes);
    SSLFreeBuffer(&hashCtx);
    return err;

}

```

### Swift

```swift
class Person {
  var residence: Residence?
}

class Residence {
  var rooms = [Room]()
  var numberOfRooms: Int {
    return rooms.count
  }


  subscript(i: Int) -> Room {
    get {
      return rooms[i]
    }
    set {
      rooms[i] = newValue
    }
  }

  func printNumberOfRooms() {
    print("The number of rooms is \(numberOfRooms)")
  }

  var address: Address?

}
```
