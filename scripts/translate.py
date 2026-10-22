"""Translate non-English titles, summaries and descriptions into English.

Uses free, open-source Argos Translate models (OpenNMT / CTranslate2) run
locally on the GitHub runner: no API key, no text sent to a third party.
Only the inference engine (ctranslate2 + sentencepiece) is installed, not the
full argostranslate package. Language detection uses `langdetect`.

Each translated field keeps its original text in `<field>_original` and its
source language (ISO code) in `<field>_lang`. Translations are cached in
data/translations.json so a text is translated once.
"""
import hashlib
import io
import json
import os
import re
import urllib.request
import zipfile

from common import DATA, ROOT, UA, clean, load, now_iso, record_health, save

CACHE_DIR = os.path.join(ROOT, ".argos-cache")
INDEX_URL = "https://raw.githubusercontent.com/argosopentech/argospm-index/main/index.json"

# Language hints for feeds that publish in one language
CERT_LANG = {"NCSC NL": "nl", "CSIRT Italia": "it", "CERT-FR": "fr", "CERT-UA": "uk"}
GDELT_LANG = {
    "french": "fr", "german": "de", "spanish": "es", "italian": "it", "dutch": "nl", "polish": "pl",
    "portuguese": "pt", "swedish": "sv", "finnish": "fi", "danish": "da", "czech": "cs", "slovak": "sk",
    "slovenian": "sl", "hungarian": "hu", "romanian": "ro", "bulgarian": "bg", "greek": "el",
    "lithuanian": "lt", "latvian": "lv", "estonian": "et", "ukrainian": "uk", "russian": "ru",
    "turkish": "tr", "chinese": "zh", "japanese": "ja", "korean": "ko", "arabic": "ar", "hebrew": "he",
    "indonesian": "id", "vietnamese": "vi", "thai": "th", "hindi": "hi", "persian": "fa", "norwegian": "nb",
    "catalan": "ca", "albanian": "sq", "irish": "ga", "malay": "ms", "english": "en",
}
DETECT_MAP = {"zh-cn": "zh", "zh-tw": "zt", "no": "nb", "pt": "pt"}

# Fields to translate per data file
TARGETS = {
    "alerts.json": ["title", "summary"],
    "incidents.json": ["title", "summary"],
    "news.json": ["title"],
    "claims.json": ["description"],
}

_index = None
_models = {}


def _key(lang, text):
    return hashlib.sha1(f"v2|{lang}|{text}".encode()).hexdigest()[:20]


_why = {}  # lang -> reason a model could not be loaded


def _get(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def available():
    global _index
    if _index is None:
        _index = {p["from_code"]: p for p in json.loads(_get(INDEX_URL, 60))
                  if p.get("to_code") == "en" and p.get("type", "translate") == "translate"}
    return _index


def _find_model_dir(root):
    for d, _, files in os.walk(root):
        if "model.bin" in files:
            return d
    return None


def _find_sp(root):
    for d, _, files in os.walk(root):
        for f in files:
            if f.endswith(".model") and "sentencepiece" in f:
                return os.path.join(d, f)
    return None


def model(lang):
    """Load (downloading if needed) the lang->en model. Returns (translator, sp, prefix) or None."""
    if lang in _models:
        return _models[lang]
    import ctranslate2
    import sentencepiece as spm

    pkg = available().get(lang)
    if not pkg:
        _why[lang] = "no model in index"
        _models[lang] = None
        return None
    folder = os.path.join(CACHE_DIR, f"{lang}_en-{pkg.get('package_version', '0')}")
    if not _find_model_dir(folder):
        os.makedirs(folder, exist_ok=True)
        blob = None
        for link in pkg.get("links", []):
            if link.startswith("http"):
                try:
                    blob = _get(link, 300)
                    break
                except Exception as e:  # try the next mirror
                    _why[lang] = f"download failed: {str(e)[:80]}"
                    print(f"model {lang} from {link} failed: {e}")
        if blob is None:
            _models[lang] = None
            return None
        zipfile.ZipFile(io.BytesIO(blob)).extractall(folder)
    mdir, spath = _find_model_dir(folder), _find_sp(folder)
    if not mdir or not spath:
        files = [os.path.relpath(os.path.join(d, f), folder) for d, _, fs in os.walk(folder) for f in fs][:12]
        _why[lang] = f"unexpected package layout: {files}"
        _models[lang] = None
        return None
    prefix = None
    for d, _, files in os.walk(folder):
        if "metadata.json" in files:
            try:
                prefix = json.load(open(os.path.join(d, "metadata.json"))).get("target_prefix") or None
            except Exception:
                pass
    try:
        tr = ctranslate2.Translator(mdir, device="cpu", compute_type="int8", inter_threads=2, intra_threads=2)
        sp = spm.SentencePieceProcessor(model_file=spath)
    except Exception as e:
        _why[lang] = f"load failed: {str(e)[:120]}"
        _models[lang] = None
        return None
    _models[lang] = (tr, sp, prefix)
    return _models[lang]


_SPLIT = re.compile(r"(?<=[.!?。！？])\s+")


def translate_texts(lang, texts):
    """Translate a list of texts from lang to English, sentence by sentence."""
    m = model(lang)
    if not m:
        return None
    tr, sp, prefix = m
    pieces, owners = [], []
    for i, t in enumerate(texts):
        for s in _SPLIT.split(t.strip()) or [t]:
            s = s.strip()
            if s:
                # keep each chunk well under the model's length limit
                while len(s) > 400:
                    cut = s.rfind(" ", 0, 400)
                    cut = cut if cut > 100 else 400
                    pieces.append(s[:cut]); owners.append(i); s = s[cut:].strip()
                pieces.append(s); owners.append(i)
    if not pieces:
        return texts
    toks = sp.encode(pieces, out_type=str)
    kw = {"target_prefix": [[prefix]] * len(toks)} if prefix else {}
    res = tr.translate_batch(toks, beam_size=2, max_batch_size=32, max_decoding_length=256, **kw)
    out = [[] for _ in texts]
    for owner, r in zip(owners, res):
        hyp = r.hypotheses[0]
        if prefix and hyp and hyp[0] == prefix:
            hyp = hyp[1:]
        # target pieces are SentencePiece tokens: "▁" marks a word start
        out[owner].append("".join(hyp).replace("\u2581", " ").strip())
    return [" ".join(o).strip() or texts[i] for i, o in enumerate(out)]


# Languages we expect in these feeds; anything else is treated as a misdetection
PLAUSIBLE = set("fr de nl it es pt pl cs sk sl hu ro bg el lt lv et fi sv da nb uk ru tr zh zt ja ko ar he ca".split())


def detect(text, hint=""):
    if hint:
        return hint
    from langdetect import DetectorFactory, detect_langs
    DetectorFactory.seed = 0
    text = re.sub(r"https?://\S+|\S+@\S+|[\d_/|#*-]+", " ", text).strip()
    if len(re.findall(r"[^\W\d_]", text)) < 12:
        return "en"
    try:
        best = detect_langs(text)[0]
    except Exception:
        return "en"
    code = DETECT_MAP.get(best.lang, best.lang)
    if code not in PLAUSIBLE:
        return "en"
    # only trust a confident non-English guess; short text needs more confidence
    if best.prob < (0.97 if len(text) < 60 else 0.85):
        return "en"
    return code


def _hint(fname, rec):
    if fname == "alerts.json":
        return CERT_LANG.get(rec.get("cert", ""), "")
    if fname == "news.json":
        return GDELT_LANG.get(str(rec.get("language", "")).lower(), "")
    return ""


def cmd_translate():
    cache = load("translations.json", {})
    used, stats, errors = set(), {}, []
    try:
        langs_ok = set(available())
    except Exception as e:
        record_health("translation", False, error=f"model index unavailable: {e}")
        return
    for fname, fields in TARGETS.items():
        rows = load(fname, [])
        if not rows:
            continue
        todo = {}  # lang -> list of (row, field, text)
        for r in rows:
            hint = _hint(fname, r)
            for f in fields:
                orig = r.get(f + "_original") or r.get(f) or ""
                if not orig:
                    continue
                lang = r.get(f + "_lang") or detect(orig, hint)
                if lang == "en":
                    r.pop(f + "_lang", None)
                    continue
                r[f + "_lang"] = lang
                k = _key(lang, orig)
                used.add(k)
                if k in cache:
                    r[f + "_original"], r[f] = orig, cache[k]
                elif lang in langs_ok:
                    todo.setdefault(lang, []).append((r, f, orig))
                else:
                    r[f + "_original"] = orig
                    stats[f"untranslated:{lang}"] = stats.get(f"untranslated:{lang}", 0) + 1
        for lang, items in todo.items():
            try:
                out = translate_texts(lang, [t for _, _, t in items])
            except Exception as e:
                out = None
                errors.append(f"{lang}: {str(e)[:120]}")
            if not out:
                if not any(e.startswith(lang + ":") for e in errors):
                    errors.append(f"{lang}: {_why.get(lang, 'model unavailable')}")
                for r, f, orig in items:
                    r[f + "_original"] = orig
                continue
            for (r, f, orig), en in zip(items, out):
                en = clean(en, 400)
                cache[_key(lang, orig)] = en
                r[f + "_original"], r[f] = orig, en
            stats[lang] = stats.get(lang, 0) + len(items)
        save(fname, rows)
    # keep only translations still in use
    save("translations.json", {k: v for k, v in cache.items() if k in used})
    total = sum(v for k, v in stats.items() if not k.startswith("untranslated"))
    record_health("translation", not errors or total > 0, total,
                  error="; ".join(errors), detail={"new_translations": stats, "cached": len(used)})
