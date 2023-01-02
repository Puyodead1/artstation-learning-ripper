# ArtStation Learning Ripper v1.0.2
# By Puyodead1
# This is an ADDON for WKS-KEY

import argparse
import base64
import json
import os
import subprocess
import requests
import logging
import xmltodict
from pathlib import Path
from coloredlogs import ColoredFormatter
from base64 import b64encode
from pathvalidate import sanitize_filepath
from pywidevine.L3.cdm import deviceconfig
from pywidevine.L3.decrypt.wvdecryptcustom import WvDecrypt

# setup logger
logging.root.setLevel(logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = ColoredFormatter(
    '[%(asctime)s] %(levelname)s: %(message)s', datefmt='%I:%M:%S')
stream = logging.StreamHandler()
stream.setLevel(logging.INFO)
stream.setFormatter(formatter)
logger.addHandler(stream)

cookies = {
    # this should be a dict of cookies, I use curlconverter.com to convert posix curl to python
}

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'X-CSRF-TOKEN': 'xxxxxxxxxxxxxxxxxxxxx',
    'PUBLIC-CSRF-TOKEN': 'xxxxxxxxxxxxxx',
    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
    'Content-Length': '0',
    'Origin': 'https://www.artstation.com',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Cache-Control': 'max-age=0',
    'TE': 'trailers',
}

session = requests.Session()
session.headers.update(headers)
session.cookies.update(cookies)

course_url = "https://www.artstation.com/api/v2/learning/courses/{hash}/autoplay.json"
series_url = "https://www.artstation.com/api/v2/learning/series/{hash}.json"
preplay_url = "https://www.artstation.com/api/v2/learning/chapters/{id}/preplay.json"
preplay_manifest_url = "https://content.uplynk.com/preplay/{verizon_asset_id}.json?v={v}&tc={tc}&ct={ct}&rays={rays}&singlevideolicense={single_video_license}&exp={exp}&rn={rn}&cid={cid}&drm_policy_name={drm_policy_name}&rmt={rmt}&manifest={manifest}&sig={sig}"
VAULT_FILE_PATH = Path(os.getcwd(), "artstation.keys")


def get_vault() -> list[str]:
    if VAULT_FILE_PATH.exists():
        with VAULT_FILE_PATH.open() as vault_file:
            return json.load(vault_file)
    else:
        # create vault file with empty array
        with VAULT_FILE_PATH.open("w") as vault_file:
            json.dump([], vault_file)
        return []


def save_vault(vault: list[str]):
    with VAULT_FILE_PATH.open("w") as vault_file:
        json.dump(vault, vault_file)


def save_key_to_vault(keys: list[str], resource: str):
    VAULT = get_vault()
    for l in keys:
        s = l.split(":")
        kid = s[0]
        key = s[1]
        if l in VAULT:
            logger.warning(f"+ Key {l} already in vault, skipping")
            continue
        VAULT.append({
            "kid": kid,
            "key": key,
            "resource": resource,
            "provider": "artstation",
        })
    save_vault(VAULT)


def get_key_from_vault(kid: str):
    VAULT = get_vault()
    result = next((x for x in VAULT if x["kid"] == kid), None)
    if result:
        return [f"{result['kid']}:{result['key']}"]
    else:
        return None


def WV_Function(pssh, lic_url, cert_b64=None):
    wvdecrypt = WvDecrypt(init_data_b64=pssh, cert_data_b64=cert_b64,
                          device=deviceconfig.device_herolte_4445_l3)
    widevine_license = session.post(
        url=lic_url, data=wvdecrypt.get_challenge())
    if not widevine_license.ok:
        raise Exception(
            f"[-] Failed to get license: {widevine_license.status_code} {widevine_license.text}")
    license_b64 = b64encode(widevine_license.content)
    wvdecrypt.update_license(license_b64)
    Correct, keyswvdecrypt = wvdecrypt.start_process()
    return keyswvdecrypt


def get_json(url: str):
    response = session.get(url, headers=headers, cookies=cookies)
    if not response.ok:
        raise Exception(
            f"[-] Failed to get data: [{response.status_code}] {response.text}")

    return response.json()


def get_text(url: str):
    response = session.get(url)
    if not response.ok:
        raise Exception(
            f"[-] Failed to get data: [{response.status_code}] {response.text}")

    return response.text


def post_json(url: str, data):
    response = session.post(url, data=data)
    if not response.ok:
        raise Exception(
            f"[-] Failed to get data: [{response.status_code}] {response.text}")

    return response.json()


def build_preplay_manifest_url(preplay_data: dict) -> str:
    return preplay_manifest_url.format(
        verizon_asset_id=preplay_data['cid'],
        v=preplay_data['v'],
        tc=preplay_data['tc'],
        ct=preplay_data['ct'],
        rays=preplay_data['rays'],
        single_video_license=preplay_data['singlevideolicense'],
        exp=preplay_data['exp'],
        rn=preplay_data['rn'],
        cid=preplay_data['cid'],
        drm_policy_name=preplay_data['drm_policy_name'],
        rmt=preplay_data['rmt'],
        manifest=preplay_data['manifest'],
        sig=preplay_data['sig']
    )


def download_file(url: str, output: str, format: str):
    ret_code = subprocess.Popen(
        ["yt-dlp", "--allow-unplayable", "-f", format, "-o", output, url]).wait()
    return ret_code


def shaka_decrypt(encrypted, decrypted, keys, stream=0):
    decrypt_command = [
        "shaka-packager",
        "--enable_raw_key_decryption",
        "-quiet",
        "input={},stream={},output={}".format(encrypted, stream, decrypted),
    ]
    if isinstance(keys, list):
        for key in keys:
            decrypt_command.append("--keys")
            decrypt_command.append("key={}:key_id={}".format(key[1], key[0]))
    else:
        decrypt_command.append("--keys")
        decrypt_command.append("key={}:key_id={}".format(keys[1], keys[0]))
    wvdecrypt_process = subprocess.Popen(
        decrypt_command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    stdoutdata, stderrdata = wvdecrypt_process.communicate()
    ret_code = wvdecrypt_process.wait()
    return ret_code


def get_service_certificate(license_url):
    response = session.post(
        url=license_url, data=base64.b64decode("CAQ=").decode("utf8"))
    if response.status_code != 200:
        raise Exception(
            f"[-] Error fetching service certificate: [{response.status_code}] {response.reason}: {response.content}")

    return b64encode(response.content)


def merge_mkv(audio, video, final):
    ret_code = subprocess.Popen(
        [
            "mkvmerge",
            "--priority",
            "lower",
            "--output",
            final,
            "--language",
            "0:eng",
            "(",
            video,
            ")",
            "--language",
            "0:eng",
            "(",
            audio,
            ")",
            "--track-order",
            "0:0,1:0"
        ]).wait()
    if ret_code != 0:
        raise Exception(
            f"[-] Failed to merge audio and video: non-zero return code {ret_code}")
    return ret_code


def download_aria(url, file_dir, filename):
    """
    @author Puyodead1
    """
    args = [
        "aria2c", url, "-o", filename, "-d", file_dir, "-j16", "-s20", "-x16",
        "-c", "--auto-file-renaming=false", "--summary-interval=0"
    ]
    proc = subprocess.Popen(
        args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT
    )
    stdoutdata, stderrdata = proc.communicate()
    ret_code = proc.wait()
    if ret_code != 0:
        raise Exception(
            f"[-] Failed to download file: non-zero return code {ret_code}")
    return ret_code


def process_lecture(series_name: str, part_dir: Path, lecture: dict):
    lecture_title = lecture['title']
    lecture_slug = lecture['slug']
    lecture_id = lecture['id']
    lecture_position = lecture['position']
    verizon_asset_id = lecture["video"]["verizon_asset_id"]
    subtitles = lecture["subtitles"]
    lecture_filename = f"{series_name} - Part {lecture_position} - {lecture_title}"
    lecture_enc_audio_filename = f"{lecture_filename}.enc.m4a"
    lecture_enc_video_filename = f"{lecture_filename}.enc.mp4"
    lecture_dec_audio_filename = f"{lecture_filename}.dec.m4a"
    lecture_dec_video_filename = f"{lecture_filename}.dec.mp4"
    lecture_subtitle_filename = f"{lecture_filename}.srt"
    lecture_final_filename = f"{lecture_filename}.mkv"

    enc_audio_filepath = sanitize_filepath(
        Path(part_dir, lecture_enc_audio_filename), platform="auto")
    enc_video_filepath = sanitize_filepath(
        Path(part_dir, lecture_enc_video_filename), platform="auto")
    dec_audio_filepath = sanitize_filepath(
        Path(part_dir, lecture_dec_audio_filename), platform="auto")
    dec_video_filepath = sanitize_filepath(
        Path(part_dir, lecture_dec_video_filename), platform="auto")
    subtitle_filepath = sanitize_filepath(
        Path(part_dir, lecture_subtitle_filename), platform="auto")
    final_filepath = sanitize_filepath(
        Path(part_dir, lecture_final_filename), platform="auto")

    if final_filepath.exists():
        logger.warning(f"[+] {lecture_filename} already exists, skipping")
        return

    logger.info(f"[+] Processing chapter {lecture_title}")

    # get lecture data
    post_data = {
        'verizon_asset_id': verizon_asset_id,
        'rmt': 'wv',
        'manifest': 'mpd'
    }
    preplay = post_json(preplay_url.format(id=lecture_id), post_data)
    preplay_manifest = build_preplay_manifest_url(preplay)
    preplay_manifest_data = get_json(preplay_manifest)
    license_url = preplay_manifest_data["drm"]["widevineLicenseURL"]
    playURL = preplay_manifest_data["playURL"]

    logger.info(f"[+] Processing {lecture_title} manifest...")

    xml = get_text(playURL)
    manifest = xmltodict.parse(xml)

    audio_kid = manifest["MPD"]["Period"]["AdaptationSet"][0][
        "ContentProtection"][0]["@cenc:default_KID"].replace("-", "")
    video_kid = manifest["MPD"]["Period"]["AdaptationSet"][1][
        "ContentProtection"][0]["@cenc:default_KID"].replace("-", "")
    audio_pssh = manifest["MPD"]["Period"]["AdaptationSet"][0]["ContentProtection"][1]["cenc:pssh"]["#text"]
    video_pssh = manifest["MPD"]["Period"]["AdaptationSet"][1]["ContentProtection"][1]["cenc:pssh"]["#text"]

    # download lecture audio
    if not enc_audio_filepath.exists() or not dec_audio_filepath.exists():
        logger.info(f"[+] Downloading audio for lecture {lecture_title}...")
        download_file(playURL, enc_audio_filepath, "bestaudio")

    # download lecture video
    if not enc_video_filepath.exists() or not dec_video_filepath.exists():
        logger.info(f"[+] Downloading video for lecture {lecture_title}...")
        download_file(playURL, enc_video_filepath, "bestvideo")

    if not dec_audio_filepath.exists() and not dec_video_filepath.exists():
        logger.info("[+] Checking for existing audio keys...")
        audio_keys = get_key_from_vault(audio_kid)

        logger.info("[+] Checking for existing video keys...")
        video_keys = get_key_from_vault(video_kid)

        if not audio_keys or not video_keys:
            logger.info("[+] Fetching decryption keys...")
            logger.info("[+] Fetching service certificate...")
            cert_data_b64 = get_service_certificate(license_url)

            if not audio_keys:
                logger.info(
                    "[-] Audio Key not found in vault, license will be requested")
                logger.info("[+] Fetching audio license...")
                audio_keys = WV_Function(
                    audio_pssh, license_url, cert_data_b64)
                logger.info("[+] Saving audio key to vault...")
                try:
                    save_key_to_vault(audio_keys, lecture_filename)
                except Exception as e:
                    raise Exception(
                        f"[-] Failed to save audio key to vault: {e}")

            if not video_keys:
                logger.info(
                    "[-] Video Key not found in vault, license will be requested")
                logger.info("[+] Fetching video license...")
                video_keys = WV_Function(
                    video_pssh, license_url, cert_data_b64)
                logger.info("[+] Saving video key to vault...")
                try:
                    save_key_to_vault(video_keys, lecture_filename)
                except Exception as e:
                    raise Exception(
                        f"[-] Failed to save video key to vault: {e}")
        else:
            logger.info("[+] Found keys in vault, skipping license request")

        formatted_audio_keys = []
        for key in audio_keys:
            kid, key = key.split(":")
            logger.info(f"[+] AUDIO KEY; {kid}:{key}")
            formatted_audio_keys.append((kid, key))

        formatted_video_keys = []
        for key in video_keys:
            kid, key = key.split(":")
            logger.info(f"[+] VIDEO KEY; {kid}:{key}")
            formatted_video_keys.append((kid, key))

        audio_key = next(
            (x for x in formatted_audio_keys if x[0] == audio_kid), None)
        video_key = next(
            (x for x in formatted_video_keys if x[0] == video_kid), None)

        if not audio_key:
            raise Exception(f"[-] Unable to find audio key for {audio_kid}")

        if not video_key:
            raise Exception(f"[-] Unable to find video key for {video_kid}")

        logger.info(f"[+] Matched audio key: {audio_kid}:{audio_key}")
        logger.info(f"[+] Matched video key: {video_kid}:{video_key}")

        # decrypt audio
        if not dec_audio_filepath.exists():
            logger.info(f"[+] Decrypting audio for lecture {lecture_title}...")
            shaka_decrypt(
                enc_audio_filepath, dec_audio_filepath, audio_key)

        # decrypt video
        if not dec_video_filepath.exists():
            logger.info(f"[+] Decrypting video for lecture {lecture_title}...")
            shaka_decrypt(
                enc_video_filepath, dec_video_filepath, video_key)
    else:
        logger.info(f"[+] Skipping decryption for {lecture_title}...")

    if not final_filepath.exists():
        # merge audio and video
        merge_mkv(dec_audio_filepath, dec_video_filepath, final_filepath)
    else:
        logger.info(f"[+] Skipping merging for {lecture_title}...")

    # download srt subtitles
    if not subtitle_filepath.exists():
        subtitle = next(
            (x for x in subtitles if ".srt" in x["file_url"] and x["locale"] == "en"), None)
        if subtitle:
            logger.info(
                f"[+] Downloading subtitles for lecture {lecture_title}...")
            download_aria(
                subtitle["file_url"], part_dir, lecture_subtitle_filename)
        else:
            logger.warning(
                f"[-] Unable to find subtitles for lecture {lecture_title}")

    # cleanup temp files
    enc_audio_filepath.unlink(missing_ok=True)
    enc_video_filepath.unlink(missing_ok=True)
    dec_audio_filepath.unlink(missing_ok=True)
    dec_video_filepath.unlink(missing_ok=True)

    logger.info(f"[+] Finished processing {lecture_title}")


def process_series(series_hash_id):
    series = get_json(series_url.format(hash=series_hash_id))

    series_name = series["title"]
    series_slug = series["slug"]
    parts = series["courses"]  # these are the "parts" of the course
    series_dir = sanitize_filepath(
        Path(base_dl_dir, series_slug), platform="auto")

    if not series_dir.exists():
        series_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"[+] Course: {series_name}; Courses: {len(parts)}")

    for part in parts:
        part_name = part["title"]
        part_slug = part["slug"]
        chapters = part["chapters"]
        part_index = parts.index(part) + 1
        part_dir = sanitize_filepath(Path(
            series_dir, f"{part_index:02d} {part_name}"), platform="auto")

        if not part_dir.exists():
            part_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            f"[+] Part: {part_index:02d} {part_name}; Chapters: {len(chapters)}")

        for chapter in chapters:
            try:
                process_lecture(series_name, part_dir, chapter)
            except Exception:
                logger.exception(
                    f"[-] Failed to process chapter for part {part_slug}")


def process(course):
    course_name = course["title"]
    course_slug = course["slug"]
    chapters = course["chapters"]
    course_dir = sanitize_filepath(
        Path(base_dl_dir, course_slug), platform="auto")

    if not course_dir.exists():
        course_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"[+] Course: {course_name}; Chapters: {len(chapters)}")

    for chapter in chapters:
        try:
            process_lecture(course_name, course_dir, chapter)
        except Exception:
            logger.exception(
                f"[-] Failed to process chapter for series {course_name}")


if __name__ == "__main__":
    logger.info("Artstation Course Downloader")
    base_dl_dir = sanitize_filepath(
        Path(os.getcwd(), "artstation"), platform="auto")

    parser = argparse.ArgumentParser(
        description='Artstation Course Downloader')
    parser.add_argument('hash', type=str, help="Course Hash", metavar="hash")
    parser.add_argument("-d", "--debug", dest="debug",
                        action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    hash = args.hash
    if args.debug:
        logging.root.setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        stream.setLevel(logging.DEBUG)

    try:
        course = post_json(course_url.format(hash=hash), None)

        series_hash_id = course["series_hash_id"]
        if series_hash_id:
            logger.info("[+] Processing as series")
            process_series(series_hash_id)
        else:
            logger.info("[+] Processing as single course")
            process(course)

    except Exception:
        logger.exception("[-] Exception")
