# Lab 7: Natural-Language Network Controller

A Python pipeline that turns a plain-language network policy into OpenFlow rules on a live Mininet switch. Translation uses Gemini. Speech uses a local Whisper model. Nothing is installed until you confirm it.

## Topology

One OpenFlow 1.3 switch, `s1`, connected to Ryu at `10.0.0.211:6653` (`simple_switch_13` and `ofctl_rest` on port 8080).

| Host | IP | MAC | Port |
| --- | --- | --- | --- |
| h1 | 10.0.0.1 | 00:00:00:00:00:01 | 1 |
| h2 | 10.0.0.2 | 00:00:00:00:00:02 | 2 |
| h3 | 10.0.0.3 | 00:00:00:00:00:03 | 3 |
| h4 | 10.0.0.4 | 00:00:00:00:00:04 | 4 |

Start the network on the Mininet VM:

```bash
sudo python3 topo_lab7.py
```

The script checks that the switch is connected, runs `pingall`, writes the result to `/tmp/lab7_verify.txt`, and opens the Mininet CLI.

## Setup

Requires Python 3.13 or newer and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

Create a `.env` file in the project root. It is gitignored.

```bash
GEMINI_API_KEY=your-key-here
```

Voice input also needs `ffmpeg` on the machine that records audio. The first voice run downloads the free local Whisper `base.en` model.

Translation uses Gemini `gemini-3.5-flash-lite`. Transcription uses local Whisper, not the paid OpenAI API.

## Commands

Translate one sentence and print the JSON. This does not touch the network.

```bash
uv run lab7 "Block all traffic from h1 to h3"
```

Translate, validate, and install after you answer `yes`:

```bash
uv run lab7-controller
```

Record from the microphone for 5 seconds, then follow the same confirm step. Pass a number to record longer.

```bash
uv run lab7-voice
uv run lab7-voice 8
```

In the Mininet CLI, check what was installed:

```text
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

## What happens to an intent

1. `translate_intent()` asks Gemini for one JSON object matching the schema in `src/lab7/schema.py`.
2. `validate_policy()` rejects unknown hosts, incomplete objects, `prioritize` and `rate_limit` actions, rules that contradict each other, and rules that contradict a policy already on `s1`. A rejection is printed and nothing is installed.
3. You confirm with `Apply this policy? (yes/no)`.
4. `apply_policy()` installs `block` and `allow` rules on `s1` through Ryu's REST API.

"All traffic" is installed as IPv4. ARP stays with the learning switch so hosts can still resolve each other. A narrower rule at a higher priority is allowed to override a broader one, which is how "allow only ICMP" is expressed: allow ICMP at priority 200, drop other IPv4 at priority 100.
