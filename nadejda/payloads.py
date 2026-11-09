"""Fake payloads used by the zapret-compatible desync presets.

The blobs are taken from the MIT-licensed
https://github.com/Flowseal/zapret-discord-youtube project (which in turn
uses bol-van/zapret).  Keeping the exact payloads matters: the provider's
DPI recognises them and stores the decoy SNI, while the real server
discards them because they are shorter than the real stream or carry a
broken checksum/TTL.
"""

from __future__ import annotations

import base64

# name -> base64 encoded bytes
_B64: dict[str, str] = {
    "tls_4pda": (
        "FgMBARcBAAETAwPVrVUrQsTGotVGIvMbPEH25dn0j4ZtNsRufaktQBDccCD5rt1UeZalto2N3roA"
        "q8BzXdZkQMGyarpm26D+zH8cMwAoEwITAcAswCvAMMAvwCTAI8AowCfACsAJwBTAEwCdAJwAPQA8"
        "ADUALwEAAKIAAAAMAAoAAAc0cGRhLnRvAAUABQEAAAAAACsABQQDBAMDAA0AGgAYCAQIBQgGBAEF"
        "AQIBBAMFAwIDAgIGAQYDACMAAAAKAAgABgAdABcAGAALAAIBAAAQAAsACQhodHRwLzEuMQAzACYA"
        "JAAdACDaD8GK2PFVoo8m0b5PMmHdPVk9qQXpr9vZFG31WHnWXgAxAAAAFwAA/wEAAQAALQACAQE="
    ),
    "tls_google": (
        "FgMBAqQBAAKgAwNTG1uXNdJx78bAizzAKwMbiq+pkn0u66h1d29m9srMVCCtyCO678EyIeenMm4u"
        "WVx3AbBZ62iWgSmeFYTq4Kp2ygAiEwETAxMCwCvAL8ypzKjALMAwwArACcATwBQAnACdAC8ANQEA"
        "AjUAAAATABEAAA53d3cuZ29vZ2xlLmNvbQAXAAD/AQABAAAKAA4ADAAdABcAGAAZAQABAQALAAIB"
        "AAAjAAAAEAAOAAwCaDIIaHR0cC8xLjEABQAFAQAAAAAAIgAKAAgEAwUDBgMCAwASAAAAMwBrAGkA"
        "HQAgc9SrNzRkNyVefiBmQR2P18zGZEMhns39hokBKFzEXX8AFwBBBNorhDIiHjDbOxxivaYzI7xF"
        "Wn577hf1dTS3ODhb/k3UxEB8lo2gLZ06wP5KkAL9V7X6U86Xaon5v0ZCkn4fAYUAKwAJCAMEAwMD"
        "AgMBAA0AGAAWBAMFAwYDCAQIBQgGBAEFAQYBAgMCAQAtAAIBAQAcAAJAAQAbAAcGAAEAAgAD/g0B"
        "GQAAAQADyQAg1tH5QJXQtpGsnLZ4sl3WzXjKncSRlI0PwQMvsrUduz0A7+jN/qbb6Q5HuiaQqvST"
        "/oy6dLwuum7WYehHi1EyrpAdTQt/rMO4TdE4G/69LMtoWuVGvwx3ktK9d7cysemsULSnXn925UTN"
        "xExeMxXRYmYfsTKySAwL9EhfNNI+By6BWCPqkmwuLSMcbvPgeo8l2gCcRvAG7IxWFkCQ87a6bflX"
        "x26x/EpfQ27LP69kZedx/BmTn4YjB+uYwTr6H105Sop8MxMpTMztwbhy3kTi1WIEiDScrdMl9ovT"
        "stmTj9Hb3EpUBk2qrgVb0Z/8vvmt+TA2A1/dCCIJFH7gGKfNtib7S6Lc6+te2MKDoMqJGmt7"
    ),
    "tls_sferum": (
        "FgMBApABAAKMAwNW2zrx+v9+nJmKhejwd4GqEnzPUGYWUKsHoGl+pRlULiBDQBFolqGHgCHehfNf"
        "O78jq4VHWH5ImBhlM8GmvF9s9wAiEwETAxMCwCvAL8ypzKjALMAwwArACcATwBQAnACdAC8ANQEA"
        "AiEAAAASABAAAA13d3cuc2ZlcnVtLnJ1ABcAAP8BAAEAAAoADgAMAB0AFwAYABkBAAEBAAsAAgEA"
        "ACMAAAAQAA4ADAJoMghodHRwLzEuMQAFAAUBAAAAAAAiAAoACAQDBQMGAwIDADMAawBpAB0AINYy"
        "6w64rRVZQF95HPmootIWfEROy9OJVtzDzPiO5pN0ABcAQQQXgnxnVLSULbpvUOyItVa3TomCtuzp"
        "1+EsWirL50s6H8f53qyVcgj2iiODB+LgDCo/ELeoFcHdxtcR5TOCUiclACsABQQDBAMDAA0AGAAW"
        "BAMFAwYDCAQIBQgGBAEFAQYBAgMCAQAtAAIBAQAcAAJAAf4NARkAAAEAATYAIHHTbv/+aYySLH5+"
        "/iu4LIpUdhyi2m59wftseOvm6yY+AO8wDGY9ML55p4kLMc0CKjuSF9mv1D8EYjLY8RX3qrhVtyQ0"
        "R6LcEW+CzQEe80cThr2DbUyEZidcvBb/PfG9Ww4pMv1TR5nQVFfJUSxc8JvDMMqNZy2Sm9Ov8CBi"
        "9CoLcdiM3XuNvEKqB9r7w2rn7BcXKc9qHrillGcnXwJlrBUJLvcwio4zF8iCrXDlrIoVkagfamSY"
        "DjHu1fJGH0G/7Wzoj6gjUEO+gf2peZXUroavNKdSbTkTmVd177gikT+F13qqZBPcKiCv3NiyZ78H"
        "7/zBDdfOwbvYSGkg9RfRDIdgSPnjdIOdVCGOmEm9R0r8lw=="
    ),
    "stun": (
        "AAEAUCESpEJaS0t1aEd4ZXBuZDAABgAJUUJ6UDp0bldrAAAAwFcABAAAA+eAKgAItrzve7P3KJgA"
        "JQAAACQABG4AHv8ACAAUqk+U+R/1zr7f7J5mrdPdm7eV7W6AKAAEKx+2NQ=="
    ),
    "stun2": (
        "AAEAZCESpELTinHFLpS2D0PpHagABgAMck05WGFRMmtQN1ZjgCIAEEN1c3RvbVNUVU4vMS4wMDEA"
        "JAAEaryR44AqAAgXxJti2DWu8QAIABROkyfasWUM+HlC3hasV4M55gt0zQAlAACAVQAEMfeMSoAo"
        "AASWLeFz"
    ),
    "quic_google": (
        "wwAAAAEIeOeYRrvzeYQAAESesuIbTYvML8k+74FJlUpbpjZLkRkbfQ7pPzj/kZL9Fu+3ogPlQ8dy"
        "MeP89o8Auy/DSwZaokXfGeuOwoSnfRtQe3OzcZK8imo9mFgmDBxr+y10Kbw8odbQHHk3KTKRDD0/"
        "8g5SJAkQBIKWNLqrjZ3+1tCq9p6GcDAc3qo+UCwnJkD6S+3zJDKp/T605OBNXZ0CWT78aGf6p7S4"
        "qYfZIhlTwaLpC3DRfnoU6fjOealCm82TouI15OZz2SddeAM94DLpdzpR6RsiF50yvp6XhGGrtG4a"
        "qVV+SzXrwxUkgyMrL8hjMlEGvRjXS7KHVda1WHEENZabAalpnEbSY4+7q+Tr21kWGdnpaXbSUHc9"
        "b+m8+EjZ9uSeFiAaTZuqjCrg8Awq/bM9kmxDHbj0SrXxGSUovKcBmjQg7N8N641Stbd0FYC2MKEL"
        "nYtR3ZaDLCwz0eZsJKze/qh+ta8RSm0E97GPcKXE17ZdbfVt/eF+77Aq+J85nWxlCheLfrBJqNN2"
        "DDbV56uKq/9VIWHR29TXY/vWQ0UHzPn5KpG9VO2M4wjMzZoNfgTY9YcA+ClVuFOM0BHuCg6x2LAt"
        "sR8+Ofr6F0hh/BJzTmL1+dWoznqhCeW+PC4x9NQde8tShTbnhFpwuCRL1S0c+Py2rvQJtGzbj9NQ"
        "Cz+jHaSTpZ35hbdQabjb6jWtKB2Ws/tc3WSZgzVVSXLD2dOgwXCwbhp7vbEsQzBPAG8zcg01mp3z"
        "V3bA9u0N66Ne0on5Y30UI79cXsBhwuqivmYW2xpHNT+o8LL7ZhmimySIExeyLDWSOSSfPu33tffn"
        "Il4Pjl48p0G3BRdr3SnqhmW1DQFKl1XODREQTAwL5dYu00NgZ9gE9NHj6UGv0Wim7q9FVzLTK3C0"
        "nUrs2EVPBZhOcKaOgOHz8L4T06vK02haE+J/n1NsKxQffG9eOsZvmY/G8iAPd4rnRQV8w1vEPgcw"
        "yIgpAfREMDEjDZo0RLpAdW4HQ0gBmuFjeKSQ3yRQhRawu4mkrZOf6vfZRS6Wt74wx0s4CUSUwVyy"
        "U+WgHMPnWTrljlkoz61LHXDtedEZbg/lD1vjA3pt2/rYmYxmz7+P8+0ozYu4WAlRxG+BwMWZP0qv"
        "nwNQNtYUEHb9i/ffKVcW/IHO7/nSSb4JII/z5+oH7otIVVHSEqhxdAWZsDzKjCFInpRjxGL3awJB"
        "Hnq+ULxEB3+nQbL6sQCjexBGocISAJ9oSXItUcPc6tBxeA/L97oMOpOyFMjR/OTYNWRJjKcDEw7U"
        "ugROORI+ODAsOpgLte4By2IsGyMp7Ehsi45ZNYgT+OleAgSdkK0EIbkWgQE30NAVIERobsj6FGuI"
        "KLzlpVEIb296FBO7PbnJX3wtMjn3zF1wTxlKWyJJc/QshKIFdu9iOKzmx09T+RJuNApwts1ITGtR"
        "Dc/RiHX6Zuihxw2lZHiKUXKyuNz1EzOj8shdnD8CkEawlP+301xKA9Gha+qp7SeDdC+KqFHKDFxk"
        "knOqOB3ZDJUijL+9n7RbDu32TGnEaaJCkE+VQEr94woNA8SxigFvW7dKtpEGSqPticyVBQsiI0at"
        "DHBW"
    ),
    "discord_udp": (
        "xQAAAAEUVh93DRgo0u2XGqyFS2TKLaqd+swURITinVcRj8DjEGInusk86Gu9TfMAgAAEfJaoPPDy"
        "vT9zJbEiVwMGIw5Ys60gJn9QJ7/kp0KlkYWHOTFqiEucEyzVtRucADsK3x3CDdqJ8ldDvM5t13R9"
        "H0UiXhvBlhwPblimMjr7er2VOwnW4VhfgtiMmQeCB3ggCSFxwsTwonqDGjDyiV83LFNNlAVT5XkV"
        "a8SIjaNqNnLaiGY5+T6CKv/yA1Pi4VjaAGpI1Wil4sWxzBRmE3HHST3BIbCtmmcmpGCGbSaxnEUF"
        "1llZE15KbLx99uFy35osxJoC1/eoiuQJs85kOZWaSIHFaEfRxsPvpl4GXX/9mZ1JR14onVHcnMqO"
        "uF2yEULizWC6oxJ/J7kb6SjLyrbOUlM12SmiSEjpSM1pYuEy/3BKZK1qrQTftVsIlnzVEmCJhGmc"
        "kXdaE3BU7pZ3pV8oPaGAVQ52wWhk9RBhDT+w0P1C7ZtyoPrrfidM18FqRl3xqQwrpkDhog/PokKq"
        "Tu/rBo/rtIQYGEkOipxBNj/9FIOnni/+tM1efJtKYPa0uPa2/xCHHQuAgXTwlcawv/NmzRsV9e+1"
        "a1yk/vereIcqhya0UGc7Gn+vCmYjYdjD53doAgkmkR5H79zwbWbFMDI0J1kLJvi6w8XQwSAVHKcp"
        "B9/TTOXgd2+BnTchF5jSWGUrtPAbbdzp15kJtGKtz9w9xuj7VV2h7a934p/eKOIOdrXoVmKeH5cs"
        "cGrHrNvvDCsr9brA00Z7vNmslNzBHWnagi5pXYBdaCc/JKTR+4sbpDe1a0vq4WXKOcACJ+9VJilD"
        "oRbgfEY7WazCSRsnqQgukZx0kTA8PqrtHZ3itvSYBLbd5toRdAYBFPyPsB7pszksZGwbqxRJCWx5"
        "5txwXJl9FQ+cyKfawpC2BXDLbXRs6SQuew2AmajY7h5ZhYRxQgRSLDGYpjeQOvkF0mPi5dLBiHuo"
        "QX5gBHL5KWopjq6GlFusBNoX7w1zzrgc+J1VMvMCZ7Vdi2KwgOn2noKNfgVvHHxvCI6kKGpWRlH2"
        "mXXR3jF4k+q3Is3Am0Qm0WnMkMmnYsvWvnE3u1aZmwq8tNfSAK3q/myc1G62EsSersCx/AzpcFQb"
        "RecIuerm8dM9CsTtTVjCY4ZefCrfnh56RvNQA4O0R/Jt2ziZJL6qpGq2rHpJ/1mfL8QN4zSYPLiQ"
        "96pi1Sjon9XnXkdNO07klaEzVYGw4P1dA99a7QgpWtLJWim/VIYidAqlwFRGaSz49llb3veFWUSx"
        "gi1WXzel0z3XluNYt3Q/MnXU23C/YA1O90n3YFuCUJuNxK/8LDw8KAKSAh9HDcF7WlR/aEdHNu6M"
        "GY/sHj9RhqlhbtDGlkPyxhj1sZnw1Qon6XduojT/hpf8V/LSVqZ6j9wfJr2ikdZtWvebCdyStA5w"
        "UPP3px9q7oc4dt77sUZjGv3q7+8t5rDq1nSWtP2X/xMfngU4VVLLf+GMU0oOct0aocTLkDVxvl75"
        "FSFulQg5FDZSYtDScfw9ZYI7qoLd7zguGEXM/MyPgGT4BOEGwvJ7QsaEX1Nq4/F7F0bY6HS1touH"
        "SVGx"
    ),
    "game_udp": (
        "yAAAAAEIzr1zJpDRXwoAAETQcm5xkigD7cNr30UjfJLAej0VZ3vhSE+U6YrMeMZI2Iy3btgaWvJx"
        "CCYsg5vuc/iDzbA7VFneNg0wB49z0M+xOybjTM+ECzWv8TSKlHiZ2t2GklmVufjh0U305sF99sQI"
        "N6IYpTCsHz4e5RcXZuoEBnLY/p4k9BA3jIOEknUB8vo8+gRxfpdH94RG27FAfM9n15KER3fruYHg"
        "/YmaYRe8oTQ5jBfFYnqe5v/hngXlht+b6T+gPyIHwjKQ9suexXFMDzDXTJFy/2wwg4a31lo7hdde"
        "5SkLHZtoYFmLCozTgDbaVJ0Ax4vRW3+tXQX72JcO/nKEehEfmS150ZaRL4pgKcfWUe/pAYHxU6rs"
        "TIhflQNkn6+vPJoCJ2JJAbgtr84QVPXvFuDwRaUTjum1m3/4flMcIDsNHDb8frcfWSp4oTXG92bT"
        "fUx8IKTXCHnoM+YXJ+eiwdAQhz2uS8BrSOTcH8H0G9yZo6nIjhsy5W7eLYcq3SCYnwdg0D9/us24"
        "SiXi2t9JFiZrpJONlB/qpQFl+i6oQSERbdN0TTYPQZEmF5IBtHgbUI/tLlTwZoKovzYLrp8eEcnl"
        "mErQ/JQvwfdxPOWP4JWeOlYzVQdasH2KmKQSURPM052isv1JFXN/3eefStHDaAbYHZDs583acoeV"
        "cixuRhBly65uhgX6pqnscSx+9WTBwZsMZDSyGI6wugX1uvsmS8pIbfTJ9m/q/ItjSlwqzw03LW5s"
        "DxUTfJ05a75ii2Iw3hOZCUV7mF3D9qkwkJcckO3sZ9LueUJ5wr/1ptOr4b6R+5LatTgT7jEs50+O"
        "3Tg+hUGq4+po6b3uZzZfyEGGe5lecDnJR5btjiDzp26D7klzCGOxbJTvuV3v596krdv2NBZ+jf13"
        "N3jjYEiU6quhiRb3NRKhMD3sHZXpXKnf+fNh9sApsN76btDY5rIti/MpZ9DD1fT8N4eVh/+V/F0F"
        "jZ4MxgZtXoGaxKgQ/PNt6lCyk9OPyNzelr760byWw6HaJ2s7LlDUaxYrlJioA72hyfU8ePo4iW2q"
        "6Qc74BKxZQekvDqb5ZZoQlerKhUj+vm13jFMNFoCg8SSC5vzMYTIC5QJ20ta+zo64Bm7ZeoNrsMv"
        "d8NJ3xLdivq+j4lPqfZIkEfM8/u/Lfi4H6LxymyQhBJvJa+s88Pj1ZYyTXAhK7w1U4DROEJrcZda"
        "Kw+UtoSVZFHETO5Ua0QhM7bEU5Nra9DtvkmqdQ2db7xM4QacljjF6REgIfmv1oQC2J/3LnA6NrZJ"
        "zJC+tdqaKvU7k53yns/MYpx8t6b7i7jgyJ/3sP0setLJkPaqM1T53dCRW5ul9nEwQaYx2r94lxSR"
        "uCPXBFeKWaOZCy4VGEAuuZ08ENL7pBHDkXLJt8yY9Z+LqkKIYcb2+WXSconl7jeckq28cj3UKIlY"
        "yVRQQsZmokNO6HXceaNB6py8U1hthOERyDCK/3d9wDQGjlwPtAUlbLZQk9PLYnAn01k9m4loO6Cy"
        "vKInylTo//DYRA9pXKvh2EN42vwoFI3G0xXYbUzclz8bIAxkXQjuFyNnWd/IvDeDZFkp79/WCBUX"
        "dD3N4nHOV0emhHKXSfODswHI0tRWGfnCWhLGzG3ioEasfm71tEWwv+ktaIiCwYg+G391sPc="
    ),
}

PAYLOADS: dict[str, bytes] = {
    name: base64.b64decode(value) for name, value in _B64.items()
}


def get(name: str, default: bytes = b"") -> bytes:
    """Return a payload by name; empty string means no payload."""
    return PAYLOADS.get((name or "").strip(), default)
