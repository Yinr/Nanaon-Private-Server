(() => {
  "use strict";

  const SONG_HOST = "https://0000227.xyz";

  const SONG_DATA = [
    { id: "13100001", name: "Syanpu_no_nioigasita" },
    { id: "13100002", name: "Rikaisya" },
    { id: "13100003", name: "Bokuha_sonzai_siteinakatta" },
    { id: "13100004", name: "11ninga_atumatta_riyu" },
    { id: "13100005", name: "Yasasii_kioku" },
    { id: "13100006", name: "Sakebu_sikanai_seisyun" },
    { id: "13100007", name: "Junkan_bus" },
    { id: "13100008", name: "Jinkaku_houkai" },
    { id: "13100009", name: "Zetubou_no_hana" },
    { id: "13100010", name: "Tikatetu_teikou_syugi" },
    { id: "13100011", name: "Hutasikana_seisyun" },
    { id: "13100012", name: "Mirai_ga_arukara" },
    { id: "13100013", name: "Idaten_musume" },
    { id: "13100014", name: "Nanimo_site_agerarenai" },
    { id: "13100015", name: "Rain_of_lies" },
    { id: "13100016", name: "Tonbo_no_kimoti" },
    { id: "13100017", name: "Kimi_ha_moon" },
    { id: "13100018", name: "Romansu_no_tumiki" },
    { id: "13100019", name: "Muzui" },
    { id: "13100020", name: "Sora_no_emerarudo" },
    { id: "13100021", name: "Kaze_ha_huiteruka" },
    { id: "13100022", name: "Bokurano_kankyo" },
    { id: "13100023", name: "Kodokuha_kiraijanai" },
    { id: "13100024", name: "Poniteruha_furimukasenai" },
    { id: "13100025", name: "Jinseiha_warutsu" },
    { id: "13100026", name: "Ikirukotoni_rakuninaritai" },
    { id: "13100027", name: "Kanjo_muyoron" },
    { id: "13100028", name: "Eienha_iranai" },
    { id: "13100029", name: "Yutoseija_tsumaranai" },
    { id: "13100030", name: "Han_charhan" },
    { id: "13100031", name: "Tatoo_love" },
    { id: "13100032", name: "Soft_cream_otoshichatta" },
    { id: "13100033", name: "Moonlight" },
    { id: "13100034", name: "Bokuga_motteru_mononara" },
    { id: "13100035", name: "Raimeino_delay" },
    { id: "13100036", name: "KiwiNo_Shuchou" },
    { id: "13100037", name: "Ashi_wo_arae" },
    { id: "13100038", name: "Negai_no_manazashi" },
    { id: "13100039", name: "Kamisamani_yubiwosasareta_bokutachi" },
    { id: "13100040", name: "Yume_no_hune" },
    { id: "13100041", name: "Tachitsuteto_pawa" },
    { id: "13100042", name: "One_of_them" },
    { id: "13100043", name: "Sukito_ittanoha_usoda" },
    { id: "13100044", name: "Hiyashinsu" },
    { id: "13100045", name: "Sorawo_tondemiyo" },
    { id: "13100046", name: "Koukan_joken" },
    { id: "13100047", name: "Sukini_narunoha_jiyudashi" },
    { id: "13100048", name: "To_go_de_yoroshiku" },
    { id: "13200001", name: "Connect" },
    { id: "13200002", name: "Oath_sign" },
    { id: "13200003", name: "Koisuru_fortunecookie" },
    { id: "13200004", name: "Hasire_pengin" },
    { id: "13200005", name: "Heavy_rotation" },
    { id: "13200006", name: "Oh_my_god" },
    { id: "13200007", name: "Sakura_minnade_tabeta" },
    { id: "13200008", name: "Speed_star" },
    { id: "13200009", name: "Sentimental_crisis" },
    { id: "13200010", name: "Ignite" },
    { id: "13200011", name: "Ideal_white" },
    { id: "13200012", name: "Preserved_roses" },
    { id: "13200013", name: "Namae_no_nai_kaibutu" },
    { id: "13200014", name: "Momoiro_typhoon" },
    { id: "13200015", name: "Zousan_no_scanty" },
    { id: "13200016", name: "Aoi_stathion" },
    { id: "13200017", name: "Tokino_kawa_wo_koete" },
    { id: "13200018", name: "Shikisai" },
    { id: "13200019", name: "Kimino_shiranai_monogatari" },
    { id: "13200020", name: "Staple_stable" },
    { id: "13200021", name: "Kaerimichi" },
    { id: "13200022", name: "Marshmallow_justice" },
    { id: "13200023", name: "Ambivalent_world" },
    { id: "13200024", name: "Renai_sakyureshon" },
    { id: "13200025", name: "Sugar_sweet_nightmare" },
    { id: "13200026", name: "Purachina_deisuko" },
    { id: "13200027", name: "Wicked_prince" },
    { id: "13200028", name: "Everyday_headband" },
    { id: "13200029", name: "Nagiichi" },
    { id: "13200030", name: "Pareoha_emerarudo" },
    { id: "13200031", name: "Motto_hadenine" },
    { id: "13200032", name: "Non_stop_road" },
    { id: "13200033", name: "Adrenaline" },
    { id: "13200034", name: "Gurenge" },
    { id: "13200035", name: "From_the_edge" },
    { id: "13200036", name: "Rising_hope" },
    { id: "13200037", name: "Grilletto" },
    { id: "13200038", name: "Millenario" },
    { id: "13200039", name: "Mirror" },
    { id: "13200040", name: "Magia" },
    { id: "13200041", name: "Yuzurenai_negai" },
    { id: "13200042", name: "Flying_get" },
    { id: "13200043", name: "Iiwake_maybe" },
    { id: "13200044", name: "Gingham_check" },
    { id: "13200045", name: "Chikatto_chika_chika" },
    { id: "13200046", name: "Valentine_kiss" },
    { id: "13200047", name: "Equal_romance" },
    { id: "13200048", name: "Gyakkou" },
    { id: "13200049", name: "Sweets_parade" },
    { id: "13200050", name: "Someone_else" },
    { id: "13200051", name: "Yoruni_kakeru" },
    { id: "13200052", name: "Kaibutu" },
    { id: "13200053", name: "Gunjo" },
    { id: "13200054", name: "Fukashigi_no_karte" },
    { id: "13200055", name: "Kimino_sei" },
    { id: "13200056", name: "Meteo_inpact" },
    { id: "13200057", name: "Truth" },
    { id: "13200058", name: "Glory_days" },
    { id: "13200059", name: "Orange" },
    { id: "13200060", name: "2bunno1" },
    { id: "13200061", name: "SketchSwitch" },
    { id: "13200062", name: "Secret_base_kimiga_kuretamono" }
  ];

  const normalizeHost = (host) => {
    let value = String(host || SONG_HOST);
    while (value.endsWith("/")) value = value.slice(0, -1);
    return value;
  };

  const createSongTracks = (host) => SONG_DATA.map(({ id, name }) => ({
    id,
    name,
    url: `${host}/song/mp3/${id}_${name}.mp3`,
    image_jacket: `${host}/img/jacket/jacket_${id}.png`
  }));

  const DEFAULT_TRACKS = createSongTracks(SONG_HOST);

  const normalizeTracks = (tracks, host = SONG_HOST) => {
    if (!Array.isArray(tracks)) return [];
    const normalizedHost = normalizeHost(host);
    return tracks
      .map((track) => {
        if (typeof track === "string") {
          const url = track.trim();
          return url ? { id: "", name: "", url, image_jacket: "" } : null;
        }
        if (!track) return null;
        const id = typeof track.id === "string" ? track.id.trim() : "";
        const name = typeof track.name === "string" ? track.name.trim() : "";
        const url = typeof track.url === "string" && track.url.trim()
          ? track.url.trim()
          : id && name
            ? `${normalizedHost}/song/mp3/${id}_${name}.mp3`
            : "";
        if (!url) return null;
        return {
          id,
          name,
          url,
          image_jacket: typeof track.image_jacket === "string" && track.image_jacket.trim()
            ? track.image_jacket.trim()
            : id
              ? `${normalizedHost}/img/jacket/jacket_${id}.png`
              : ""
        };
      })
      .filter(Boolean);
  };

  const titleForTrack = (track) => {
    if (!track?.name) return "Random BGM";
    return track.name.split("_").join(" ");
  };

  const linkForTrack = (track, host) => track?.id
    ? `${host}/home#${encodeURIComponent(track.id)}`
    : "";

  const tracksFromElement = (root) => {
    const raw = root.dataset.bgmTracks
      || root.querySelector("script[type=\"application/json\"][data-bgm-tracks]")?.textContent;
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  };

  const makeElement = (tag, className) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    return element;
  };

  const INSTANCES = new WeakMap();

  class RandomBgmPlayer {
    constructor(root, options = {}) {
      if (!(root instanceof HTMLElement)) throw new TypeError("RandomBgmPlayer root must be an HTMLElement");

      this.root = root;
      this.host = normalizeHost(options.host || root.dataset.bgmHost || SONG_HOST);
      const configuredTracks = Object.prototype.hasOwnProperty.call(options, "tracks")
        ? options.tracks
        : tracksFromElement(root);
      this.tracks = normalizeTracks(configuredTracks || createSongTracks(this.host), this.host);
      this.current = -1;
      this.motionFrame = 0;
      this.coverUrl = "";
      this.playRequest = 0;

      this.buildDom();
      this.bindEvents();
      this.toggle.disabled = !this.tracks.length;
      this.setUi("idle");
      root.dataset.bgmReady = "true";
      root.__randomBgm = this;
      INSTANCES.set(root, this);
    }

    buildDom() {
      this.root.classList.add("bgm-float");
      if (!this.root.getAttribute("aria-label")) this.root.setAttribute("aria-label", "随机 BGM");

      const control = makeElement("span", "bgm-disc-control");
      this.cover = makeElement("img", "bgm-cover");
      this.cover.dataset.bgmCover = "";
      this.cover.alt = "";
      this.cover.hidden = true;

      this.toggle = makeElement("button", "bgm-toggle");
      this.toggle.dataset.bgmToggle = "";
      this.toggle.type = "button";
      this.toggle.setAttribute("aria-label", "Play random BGM");
      this.toggle.setAttribute("aria-pressed", "false");
      this.icon = makeElement("span");
      this.icon.dataset.bgmIcon = "";
      this.icon.setAttribute("aria-hidden", "true");
      this.icon.textContent = "▶";
      this.toggle.append(this.icon);
      control.append(this.cover, this.toggle);

      this.status = makeElement("span", "bgm-status");
      this.status.dataset.bgmStatus = "";
      this.status.setAttribute("role", "status");
      const titleViewport = makeElement("span", "bgm-title-viewport");
      this.trackLabel = makeElement("a", "bgm-track-name");
      this.trackLabel.dataset.bgmTrack = "";
      this.stateLabel = makeElement("span", "bgm-state");
      this.stateLabel.dataset.bgmState = "";
      titleViewport.append(this.trackLabel);
      this.status.append(titleViewport, this.stateLabel);

      this.player = makeElement("audio");
      this.player.dataset.bgmPlayer = "";
      this.player.preload = "none";
      this.root.replaceChildren(control, this.status, this.player);
    }

    bindEvents() {
      this.onToggle = () => {
        if (!this.player.paused) this.pause();
        else void this.playCurrent();
      };
      this.onEnded = () => void this.playNext();
      this.onError = () => {
        this.setUi("idle");
        this.clearSource();
      };
      this.onResize = () => this.resetTrackMotion();

      this.toggle.addEventListener("click", this.onToggle);
      this.player.addEventListener("ended", this.onEnded);
      this.player.addEventListener("error", this.onError);
      window.addEventListener("resize", this.onResize);
    }

    resetTrackMotion() {
      if (this.motionFrame) cancelAnimationFrame(this.motionFrame);
      this.trackLabel.classList.remove("is-scrolling");
      this.trackLabel.style.removeProperty("--bgm-scroll-distance");
      this.trackLabel.style.removeProperty("--bgm-scroll-duration");
      if (!this.root.classList.contains("has-track")) return;
      this.motionFrame = requestAnimationFrame(() => {
        const viewport = this.trackLabel.parentElement;
        if (!viewport) return;
        const distance = this.trackLabel.scrollWidth - viewport.clientWidth;
        if (distance > 2) {
          this.trackLabel.style.setProperty("--bgm-scroll-distance", `${distance}px`);
          this.trackLabel.style.setProperty(
            "--bgm-scroll-duration",
            `${Math.max(10, Math.min(24, 9 + distance / 18))}s`
          );
          this.trackLabel.classList.add("is-scrolling");
        }
      });
    }

    hideCover() {
      this.coverUrl = "";
      this.cover.hidden = true;
      this.cover.removeAttribute("src");
      this.cover.alt = "";
      this.cover.onload = null;
      this.cover.onerror = null;
    }

    loadCover(track) {
      const url = track.image_jacket;
      if (!url) {
        this.hideCover();
        return;
      }
      this.coverUrl = url;
      this.cover.hidden = true;
      this.cover.alt = `${titleForTrack(track)} album cover`;
      this.cover.onload = () => {
        if (this.coverUrl === url && this.root.classList.contains("has-track")) this.cover.hidden = false;
      };
      this.cover.onerror = () => {
        if (this.coverUrl === url) this.cover.hidden = true;
      };
      this.cover.src = url;
    }

    setUi(mode, track = null) {
      const active = mode === "playing" || mode === "paused";
      const currentTrack = track || (this.current >= 0 ? this.tracks[this.current] : null);
      const hasTrack = active && !!currentTrack;
      this.root.classList.toggle("has-track", hasTrack);
      this.root.classList.toggle("is-playing", mode === "playing");
      this.root.classList.toggle("is-paused", mode === "paused");
      this.toggle.setAttribute("aria-pressed", String(mode === "playing"));
      this.toggle.setAttribute(
        "aria-label",
        mode === "playing" ? "Pause random BGM" : mode === "paused" ? "Resume random BGM" : "Play random BGM"
      );
      this.icon.textContent = mode === "playing" ? "Ⅱ" : "▶";
      this.trackLabel.textContent = hasTrack ? titleForTrack(currentTrack) : "";

      const href = hasTrack ? linkForTrack(currentTrack, this.host) : "";
      if (href) {
        this.trackLabel.href = href;
        this.trackLabel.target = "_blank";
        this.trackLabel.rel = "noopener noreferrer";
      } else {
        this.trackLabel.removeAttribute("href");
        this.trackLabel.removeAttribute("target");
        this.trackLabel.removeAttribute("rel");
      }

      this.stateLabel.textContent = mode === "playing" ? "播放中" : mode === "paused" ? "暂停中" : "";
      if (hasTrack) {
        if (!currentTrack.image_jacket) this.hideCover();
        else if (this.coverUrl !== currentTrack.image_jacket) this.loadCover(currentTrack);
        else if (this.cover.complete && this.cover.naturalWidth) this.cover.hidden = false;
      } else {
        this.hideCover();
      }
      this.resetTrackMotion();
    }

    clearSource() {
      this.player.pause();
      this.player.removeAttribute("src");
      this.player.load();
    }

    chooseTrack() {
      if (!this.tracks.length) return null;
      let index = Math.floor(Math.random() * this.tracks.length);
      if (this.tracks.length > 1 && index === this.current) index = (index + 1) % this.tracks.length;
      this.current = index;
      const track = this.tracks[index];
      this.player.src = track.url;
      this.player.load();
      return track;
    }

    async playCurrent() {
      if (!this.tracks.length) return;
      const request = ++this.playRequest;
      const track = this.player.src && this.current >= 0 ? this.tracks[this.current] : this.chooseTrack();
      if (!track) return;
      this.player.volume = 0.24;
      try {
        await this.player.play();
        if (request === this.playRequest) this.setUi("playing", track);
      } catch {
        if (request === this.playRequest) {
          this.setUi("idle");
          this.clearSource();
        }
      }
    }

    pause() {
      ++this.playRequest;
      this.player.pause();
      this.setUi("paused");
    }

    async playNext() {
      const track = this.chooseTrack();
      if (!track) return;
      const request = ++this.playRequest;
      this.player.volume = 0.24;
      try {
        await this.player.play();
        if (request === this.playRequest) this.setUi("playing", track);
      } catch {
        if (request === this.playRequest) {
          this.setUi("idle");
          this.clearSource();
        }
      }
    }

    destroy() {
      if (this.motionFrame) cancelAnimationFrame(this.motionFrame);
      this.toggle.removeEventListener("click", this.onToggle);
      this.player.removeEventListener("ended", this.onEnded);
      this.player.removeEventListener("error", this.onError);
      window.removeEventListener("resize", this.onResize);
      this.player.pause();
      this.root.replaceChildren();
      this.root.dataset.bgmReady = "false";
      delete this.root.__randomBgm;
      INSTANCES.delete(this.root);
    }

    static init(root, options = {}) {
      if (typeof root === "string") root = document.querySelector(root);
      if (!(root instanceof HTMLElement)) return null;
      return INSTANCES.get(root) || root.__randomBgm || new RandomBgmPlayer(root, options);
    }
  }

  const boot = () => {
    document.querySelectorAll("[data-bgm]").forEach((root) => RandomBgmPlayer.init(root));
  };

  window.RandomBgmPlayer = RandomBgmPlayer;
  window.RandomBgm = {
    init: RandomBgmPlayer.init,
    defaultTracks: DEFAULT_TRACKS.map((track) => ({ ...track })),
    Player: RandomBgmPlayer
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
