"""
RSA Key Manager – Secure Encryptor
Modern desktop application with CustomTkinter
Compatible with Windows 11 and macOS Ventura/Sonoma/Sequoia
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Optional
import threading
import base64
import os
import json
import time
import platform
from pathlib import Path
from datetime import datetime

# Cryptography imports
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# ── Design Tokens ─────────────────────────────────────────────────────────────
COLORS = {
    "light": {
        "bg":          "#F3F3F3",
        "surface":     "#FFFFFF",
        "surface2":    "#F0F0F0",
        "border":      "#E0E0E0",
        "accent":      "#0078D4",
        "accent_dark": "#005A9E",
        "accent_text": "#FFFFFF",
        "text":        "#1C1C1E",
        "text_sec":    "#6E6E73",
        "success_bg":  "#E6F4EA",
        "success_txt": "#1A7F37",
        "error_bg":    "#FDE8E8",
        "error_txt":   "#C0392B",
        "warn_bg":     "#FFF8E1",
        "warn_txt":    "#7D5A00",
        "header_bg":   "#0078D4",
        "header_fg":   "#FFFFFF",
        "mono_bg":     "#F7F7F7",
        "toggle_bg":   "#E0E0E0",
    },
    "dark": {
        "bg":          "#202020",
        "surface":     "#2C2C2E",
        "surface2":    "#3A3A3C",
        "border":      "#48484A",
        "accent":      "#0A84FF",
        "accent_dark": "#0066CC",
        "accent_text": "#FFFFFF",
        "text":        "#F2F2F7",
        "text_sec":    "#8E8E93",
        "success_bg":  "#1A3A22",
        "success_txt": "#4CAF82",
        "error_bg":    "#3A1A1A",
        "error_txt":   "#FF6B6B",
        "warn_bg":     "#3A2E00",
        "warn_txt":    "#FFD60A",
        "header_bg":   "#1C1C1E",
        "header_fg":   "#F2F2F7",
        "mono_bg":     "#1A1A1A",
        "toggle_bg":   "#48484A",
    }
}

FONT_FAMILY = "Segoe UI Variable" if platform.system() == "Windows" else \
              "SF Pro Display" if platform.system() == "Darwin" else "Helvetica"
MONO_FONT = "Cascadia Code" if platform.system() == "Windows" else \
            "SF Mono" if platform.system() == "Darwin" else "Courier New"


def load_prefs() -> dict:
    prefs_path = Path.home() / ".rsa_manager_prefs.json"
    if prefs_path.exists():
        try:
            return json.loads(prefs_path.read_text())
        except Exception:
            pass
    return {"theme": "light"}


def save_prefs(prefs: dict):
    prefs_path = Path.home() / ".rsa_manager_prefs.json"
    try:
        prefs_path.write_text(json.dumps(prefs))
    except Exception:
        pass


# ── Tooltip ────────────────────────────────────────────────────────────────────
class Tooltip:
    def __init__(self, widget, text: str, app):
        self.widget = widget
        self.text = text
        self.app = app
        self.tw = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _event=None):
        c = self.app.c
        x = self.widget.winfo_rootx() + 10
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(
            self.tw, text=self.text,
            background=c["surface2"], foreground=c["text_sec"],
            font=(FONT_FAMILY, 11), relief="flat",
            padx=8, pady=4, borderwidth=1,
            highlightbackground=c["border"], highlightthickness=1
        )
        lbl.pack()

    def hide(self, _event=None):
        if self.tw:
            self.tw.destroy()
            self.tw = None


# ── Main Application ───────────────────────────────────────────────────────────
class RSAManagerApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.prefs = load_prefs()
        self._theme = self.prefs.get("theme", "light")
        # Set once before widgets are created; never called again after init.
        # All subsequent theme switching is handled purely by _apply_theme()
        # so we never trigger CustomTkinter's full widget-tree rebuild.
        ctk.set_appearance_mode("light" if self._theme == "light" else "dark")
        ctk.set_default_color_theme("blue")

        self.title("RSA Key Manager – Secure Encryptor")
        self.geometry("960x760")
        self.minsize(860, 680)
        self.resizable(True, True)

        # State
        self._private_key = None
        self._public_key = None
        self._encrypted_data = None  # type: Optional[bytes]
        self._decrypt_mode = tk.StringVar(value="auto")
        self._key_bits = 2048
        self._generating = False

        # Center window
        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"+{(sw-960)//2}+{(sh-760)//2}")

        self._build_ui()
        self._apply_theme()

    @property
    def c(self) -> dict:
        return COLORS[self._theme]

    # ── Theme ────────────────────────────────────────────────────────────────
    def _toggle_theme(self):
        self._theme = "dark" if self._theme == "light" else "light"
        self.prefs["theme"] = self._theme
        save_prefs(self.prefs)
        # Do NOT call ctk.set_appearance_mode() here — it destroys and
        # rebuilds every widget, which looks like an app restart.
        # _apply_theme() recolours every widget in-place instead.
        self._apply_theme()

    def _apply_theme(self):
        c = self.c
        self.configure(fg_color=c["bg"])

        # Header
        self._header_frame.configure(fg_color=c["header_bg"])
        self._header_title.configure(text_color=c["header_fg"])
        # Use a dimmed solid colour instead of unsupported 8-digit hex alpha
        sub_color = "#CCCCCC" if self._theme == "light" else "#AAAAAA"
        self._header_sub.configure(text_color=sub_color)
        self._theme_btn.configure(
            text="☀ Light" if self._theme == "dark" else "🌙 Dark",
            fg_color=c["accent_dark"], hover_color=c["accent"],
            text_color=c["accent_text"]
        )

        # Cards
        for card in self._all_cards:
            card.configure(fg_color=c["surface"], border_color=c["border"])

        # Section labels
        for lbl in self._section_labels:
            lbl.configure(text_color=c["text"])

        # Secondary labels
        for lbl in self._sec_labels:
            lbl.configure(text_color=c["text_sec"])

        # Status bar
        self._status_bar.configure(fg_color=c["surface2"])
        self._status_label.configure(text_color=c["text_sec"])
        self._key_size_label.configure(text_color=c["accent"])

        # Textboxes
        for tb in self._all_textboxes:
            tb.configure(
                fg_color=c["mono_bg"],
                border_color=c["border"],
                text_color=c["text"]
            )

        # Entries
        for ent in self._all_entries:
            ent.configure(
                fg_color=c["surface"],
                border_color=c["border"],
                text_color=c["text"]
            )

        # Key size buttons
        for btn_data in self._key_btns:
            btn, bits = btn_data
            is_sel = (bits == self._key_bits)
            btn.configure(
                fg_color=c["accent"] if is_sel else c["surface2"],
                hover_color=c["accent_dark"] if is_sel else c["border"],
                text_color=c["accent_text"] if is_sel else c["text"],
                border_color=c["accent"] if is_sel else c["border"]
            )

        # Accent buttons
        for btn in self._accent_btns:
            btn.configure(
                fg_color=c["accent"],
                hover_color=c["accent_dark"],
                text_color=c["accent_text"]
            )

        # Ghost buttons
        for btn in self._ghost_btns:
            btn.configure(
                fg_color="transparent",
                hover_color=c["surface2"],
                text_color=c["text_sec"],
                border_color=c["border"]
            )

        # Danger buttons
        for btn in self._danger_btns:
            btn.configure(
                fg_color="transparent",
                hover_color="#FFE0E0" if self._theme == "light" else "#3A1A1A",
                text_color="#C0392B" if self._theme == "light" else "#FF6B6B",
                border_color="#C0392B" if self._theme == "light" else "#FF6B6B"
            )

        # Decrypt mode toggles
        self._update_decrypt_toggle_style()

        # Dividers
        for div in self._dividers:
            div.configure(fg_color=c["border"])

        # Scroll container + scrollbar
        self._scroll_frame.configure(
            fg_color=c["bg"],
            scrollbar_button_color=c["border"],
            scrollbar_button_hover_color=c["accent"]
        )
        self._inner_frame.configure(fg_color=c["bg"])

        # Progress bar colours
        self._gen_progress.configure(
            progress_color=c["accent"],
            fg_color=c["surface2"]
        )
        self._gen_progress_label.configure(text_color=c["text_sec"])

        # Decryption output frame — only reset to neutral if showing default text
        if self._dec_output_label.cget("text") == "No decrypted output yet":
            self._dec_output_frame.configure(
                fg_color=c["surface2"],
                border_color=c["border"]
            )
            self._dec_output_label.configure(text_color=c["text_sec"])

    # ── UI Construction ──────────────────────────────────────────────────────
    def _build_ui(self):
        c = self.c

        # Collection buckets for theme application
        self._all_cards = []
        self._section_labels = []
        self._sec_labels = []
        self._all_textboxes = []
        self._all_entries = []
        self._key_btns = []
        self._accent_btns = []
        self._ghost_btns = []
        self._danger_btns = []
        self._dividers = []

        # ── Header ────────────────────────────────────────────────────────────
        self._header_frame = ctk.CTkFrame(self, fg_color=c["header_bg"],
                                          corner_radius=0, height=72)
        self._header_frame.pack(fill="x", side="top")
        self._header_frame.pack_propagate(False)

        hinner = ctk.CTkFrame(self._header_frame, fg_color="transparent")
        hinner.place(relx=0.5, rely=0.5, anchor="center")

        self._header_title = ctk.CTkLabel(
            hinner, text="🔐  RSA Key Manager – Secure Encryptor",
            font=ctk.CTkFont(FONT_FAMILY, 22, weight="bold"),
            text_color=c["header_fg"]
        )
        self._header_title.pack()

        self._header_sub = ctk.CTkLabel(
            hinner,
            text="Generate · Encrypt · Decrypt  |  Industry-standard RSA cryptography",
            font=ctk.CTkFont(FONT_FAMILY, 12),
            text_color="#CCCCCC"
        )
        self._header_sub.pack()

        self._theme_btn = ctk.CTkButton(
            self._header_frame,
            text="🌙 Dark", width=90, height=32,
            font=ctk.CTkFont(FONT_FAMILY, 12),
            corner_radius=16,
            command=self._toggle_theme
        )
        self._theme_btn.place(relx=1.0, rely=0.5, anchor="e", x=-16)

        # ── Scrollable Body ───────────────────────────────────────────────────
        self._scroll_frame = ctk.CTkScrollableFrame(
            self, fg_color=c["bg"], corner_radius=0,
            scrollbar_button_color=c["border"],
            scrollbar_button_hover_color=c["accent"]
        )
        self._scroll_frame.pack(fill="both", expand=True, padx=0, pady=0)

        self._inner_frame = ctk.CTkFrame(self._scroll_frame, fg_color=c["bg"])
        self._inner_frame.pack(fill="both", expand=True, padx=20, pady=16)

        self._build_key_section()
        self._add_divider()
        self._build_encrypt_section()
        self._add_divider()
        self._build_decrypt_section()

        # ── Status Bar ────────────────────────────────────────────────────────
        self._status_bar = ctk.CTkFrame(self, fg_color=c["surface2"],
                                        corner_radius=0, height=32)
        self._status_bar.pack(fill="x", side="bottom")
        self._status_bar.pack_propagate(False)

        self._status_label = ctk.CTkLabel(
            self._status_bar, text="Ready — no keys generated yet",
            font=ctk.CTkFont(FONT_FAMILY, 11), text_color=c["text_sec"]
        )
        self._status_label.pack(side="left", padx=12)

        self._key_size_label = ctk.CTkLabel(
            self._status_bar, text="Key: None",
            font=ctk.CTkFont(FONT_FAMILY, 11, weight="bold"),
            text_color=c["accent"]
        )
        self._key_size_label.pack(side="right", padx=12)

    def _add_divider(self):
        c = self.c
        div = ctk.CTkFrame(self._inner_frame, fg_color=c["border"], height=1)
        div.pack(fill="x", pady=16)
        self._dividers.append(div)

    def _make_card(self, parent, **kwargs):
        c = self.c
        card = ctk.CTkFrame(
            parent,
            fg_color=c["surface"],
            corner_radius=14,
            border_width=1,
            border_color=c["border"],
            **kwargs
        )
        self._all_cards.append(card)
        return card

    def _make_section_label(self, parent, text: str):
        c = self.c
        lbl = ctk.CTkLabel(
            parent, text=text,
            font=ctk.CTkFont(FONT_FAMILY, 16, weight="bold"),
            text_color=c["text"]
        )
        self._section_labels.append(lbl)
        return lbl

    def _make_sec_label(self, parent, text: str, **kwargs):
        c = self.c
        lbl = ctk.CTkLabel(
            parent, text=text,
            font=ctk.CTkFont(FONT_FAMILY, 12),
            text_color=c["text_sec"], **kwargs
        )
        self._sec_labels.append(lbl)
        return lbl

    def _make_textbox(self, parent, height=120, **kwargs):
        c = self.c
        tb = ctk.CTkTextbox(
            parent,
            height=height,
            font=ctk.CTkFont(MONO_FONT, 11),
            fg_color=c["mono_bg"],
            border_color=c["border"],
            border_width=1,
            text_color=c["text"],
            corner_radius=8,
            **kwargs
        )
        self._all_textboxes.append(tb)
        return tb

    def _make_entry(self, parent, placeholder="", **kwargs):
        c = self.c
        ent = ctk.CTkEntry(
            parent,
            placeholder_text=placeholder,
            font=ctk.CTkFont(FONT_FAMILY, 13),
            fg_color=c["surface"],
            border_color=c["border"],
            border_width=1,
            text_color=c["text"],
            corner_radius=8,
            height=40,
            **kwargs
        )
        self._all_entries.append(ent)
        return ent

    def _make_accent_btn(self, parent, text, cmd, width=140, icon=""):
        c = self.c
        btn = ctk.CTkButton(
            parent,
            text=f"{icon}  {text}" if icon else text,
            command=cmd,
            fg_color=c["accent"],
            hover_color=c["accent_dark"],
            text_color=c["accent_text"],
            font=ctk.CTkFont(FONT_FAMILY, 13, weight="bold"),
            corner_radius=10,
            height=38,
            width=width
        )
        self._accent_btns.append(btn)
        return btn

    def _make_ghost_btn(self, parent, text, cmd, width=120):
        c = self.c
        btn = ctk.CTkButton(
            parent,
            text=text,
            command=cmd,
            fg_color="transparent",
            hover_color=c["surface2"],
            text_color=c["text_sec"],
            border_color=c["border"],
            border_width=1,
            font=ctk.CTkFont(FONT_FAMILY, 12),
            corner_radius=10,
            height=34,
            width=width
        )
        self._ghost_btns.append(btn)
        return btn

    # ── Key Generation Section ───────────────────────────────────────────────
    def _build_key_section(self):
        c = self.c
        parent = self._inner_frame

        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 10))
        self._make_section_label(hdr, "🔑  Key Generation").pack(side="left")

        # Import public key (ghost)
        import_btn = self._make_ghost_btn(hdr, "⤵  Import Public Key",
                                          self._import_public_key, width=160)
        import_btn.pack(side="right")
        Tooltip(import_btn, "Load a PEM public key from file for encryption", self)

        # Key size selector card
        size_card = self._make_card(parent)
        size_card.pack(fill="x", pady=(0, 12))

        size_inner = ctk.CTkFrame(size_card, fg_color="transparent")
        size_inner.pack(padx=20, pady=14, fill="x")

        self._make_sec_label(
            size_inner, "Select key size (larger = more secure, slower to generate):"
        ).pack(anchor="w", pady=(0, 10))

        btn_row = ctk.CTkFrame(size_inner, fg_color="transparent")
        btn_row.pack(anchor="w")

        for bits, icon in [(2048, "🔒"), (3072, "🔐"), (4096, "🛡")]:
            btn = ctk.CTkButton(
                btn_row,
                text=f"{icon}  {bits}-bit",
                width=130, height=40,
                corner_radius=10,
                font=ctk.CTkFont(FONT_FAMILY, 13, weight="bold"),
                command=lambda b=bits: self._select_key_size(b)
            )
            btn.pack(side="left", padx=(0, 10))
            self._key_btns.append((btn, bits))
            labels = {2048: "Fast generation, standard security",
                      3072: "Balanced performance and security",
                      4096: "Maximum security, slower generation"}
            Tooltip(btn, labels[bits], self)

        # Progress indicator (hidden initially)
        self._gen_progress_frame = ctk.CTkFrame(size_inner, fg_color="transparent")
        self._gen_progress_frame.pack(anchor="w", pady=(10, 0), fill="x")

        self._gen_progress = ctk.CTkProgressBar(
            self._gen_progress_frame,
            mode="indeterminate",
            height=6,
            corner_radius=3,
            progress_color=c["accent"],
            fg_color=c["surface2"]
        )
        self._gen_progress_label = ctk.CTkLabel(
            self._gen_progress_frame,
            text="",
            font=ctk.CTkFont(FONT_FAMILY, 12),
            text_color=c["text_sec"]
        )

        # Generate button row
        gen_row = ctk.CTkFrame(size_inner, fg_color="transparent")
        gen_row.pack(fill="x", pady=(12, 0))

        self._gen_btn = self._make_accent_btn(
            gen_row, "Generate Keys", self._generate_keys,
            width=150, icon="⚙"
        )
        self._gen_btn.pack(side="left")
        Tooltip(self._gen_btn, "Generate a new RSA key pair", self)

        export_btn = self._make_ghost_btn(
            gen_row, "💾  Export as .pem", self._export_keys, width=150
        )
        export_btn.pack(side="left", padx=(10, 0))
        Tooltip(export_btn, "Save both keys to .pem files", self)

        # Clear all button
        c_btn = ctk.CTkButton(
            gen_row, text="🗑  Clear All",
            command=self._clear_all,
            fg_color="transparent",
            hover_color="#FFE0E0",
            text_color="#C0392B",
            border_color="#C0392B",
            border_width=1,
            font=ctk.CTkFont(FONT_FAMILY, 12),
            corner_radius=10,
            height=34, width=120
        )
        c_btn.pack(side="right")
        self._danger_btns.append(c_btn)
        Tooltip(c_btn, "Clear all keys, encrypted and decrypted data", self)

        # Keys display
        keys_row = ctk.CTkFrame(parent, fg_color="transparent")
        keys_row.pack(fill="x", pady=(0, 4))
        keys_row.columnconfigure(0, weight=1)
        keys_row.columnconfigure(1, weight=1)

        for col, (label, attr) in enumerate([
            ("Public Key (PEM)", "_pub_tb"),
            ("Private Key (PEM)", "_priv_tb")
        ]):
            card = self._make_card(keys_row)
            card.grid(row=0, column=col, padx=(0, 10) if col == 0 else (10, 0),
                      sticky="nsew")

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(padx=16, pady=12, fill="both", expand=True)

            lbl_row = ctk.CTkFrame(inner, fg_color="transparent")
            lbl_row.pack(fill="x", pady=(0, 6))
            self._make_sec_label(lbl_row, label).pack(side="left")

            copy_btn = self._make_ghost_btn(
                lbl_row, "📋 Copy",
                lambda a=attr: self._copy_textbox(a),
                width=80
            )
            copy_btn.pack(side="right")
            Tooltip(copy_btn, f"Copy {label} to clipboard", self)

            tb = self._make_textbox(inner, height=130)
            tb.pack(fill="both", expand=True)
            tb.configure(state="disabled")
            setattr(self, attr, tb)

    # ── Encryption Section ───────────────────────────────────────────────────
    def _build_encrypt_section(self):
        parent = self._inner_frame

        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 10))
        self._make_section_label(hdr, "🔒  Encryption").pack(side="left")

        card = self._make_card(parent)
        card.pack(fill="x", pady=(0, 4))

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(padx=20, pady=16, fill="both", expand=True)

        self._make_sec_label(inner, "Plaintext message:").pack(anchor="w", pady=(0, 6))

        self._msg_entry = self._make_entry(
            inner, placeholder="Enter your secret message here..."
        )
        self._msg_entry.pack(fill="x", pady=(0, 12))

        enc_row = ctk.CTkFrame(inner, fg_color="transparent")
        enc_row.pack(fill="x", pady=(0, 12))

        enc_btn = self._make_accent_btn(
            enc_row, "Encrypt Message", self._encrypt_message,
            width=170, icon="🔒"
        )
        enc_btn.pack(side="left")
        Tooltip(enc_btn, "Encrypt the plaintext using the loaded public key", self)

        # Output area
        out_row = ctk.CTkFrame(inner, fg_color="transparent")
        out_row.pack(fill="x")

        out_lbl_row = ctk.CTkFrame(out_row, fg_color="transparent")
        out_lbl_row.pack(fill="x", pady=(0, 6))
        self._make_sec_label(out_lbl_row, "Encrypted output (Base64):").pack(side="left")

        copy_enc = self._make_ghost_btn(
            out_lbl_row, "📋 Copy",
            lambda: self._copy_textbox("_enc_tb"), width=80
        )
        copy_enc.pack(side="right")
        Tooltip(copy_enc, "Copy encrypted Base64 to clipboard", self)

        self._enc_tb = self._make_textbox(out_row, height=90)
        self._enc_tb.pack(fill="x")
        self._enc_tb.configure(state="disabled")

    # ── Decryption Section ───────────────────────────────────────────────────
    def _build_decrypt_section(self):
        c = self.c
        parent = self._inner_frame

        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 10))
        self._make_section_label(hdr, "🔓  Decryption").pack(side="left")

        card = self._make_card(parent)
        card.pack(fill="x", pady=(0, 16))

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(padx=20, pady=16, fill="both", expand=True)

        # Mode toggle
        self._make_sec_label(inner, "Decryption mode:").pack(anchor="w", pady=(0, 8))

        toggle_row = ctk.CTkFrame(inner, fg_color="transparent")
        toggle_row.pack(anchor="w", pady=(0, 14))

        self._auto_btn = ctk.CTkButton(
            toggle_row, text="🤖  Auto Decrypt",
            command=lambda: self._set_decrypt_mode("auto"),
            width=160, height=36, corner_radius=8,
            font=ctk.CTkFont(FONT_FAMILY, 13, weight="bold")
        )
        self._auto_btn.pack(side="left")
        Tooltip(self._auto_btn,
                "Instantly decrypt using the current loaded private key", self)

        self._manual_btn = ctk.CTkButton(
            toggle_row, text="👤  Manual Decrypt",
            command=lambda: self._set_decrypt_mode("manual"),
            width=160, height=36, corner_radius=8,
            font=ctk.CTkFont(FONT_FAMILY, 13, weight="bold")
        )
        self._manual_btn.pack(side="left", padx=(8, 0))
        Tooltip(self._manual_btn,
                "Paste your own encrypted data and private key manually", self)

        # Manual fields (hidden by default)
        self._manual_frame = ctk.CTkFrame(inner, fg_color="transparent")

        self._make_sec_label(
            self._manual_frame, "Pasted Encrypted Data (Base64):"
        ).pack(anchor="w", pady=(0, 4))

        self._manual_enc_tb = self._make_textbox(self._manual_frame, height=70)
        self._manual_enc_tb.pack(fill="x", pady=(0, 12))
        self._all_textboxes.append(self._manual_enc_tb)

        self._make_sec_label(
            self._manual_frame, "Pasted Private Key (PEM format):"
        ).pack(anchor="w", pady=(0, 4))

        self._manual_key_tb = self._make_textbox(self._manual_frame, height=80)
        self._manual_key_tb.pack(fill="x", pady=(0, 12))
        self._all_textboxes.append(self._manual_key_tb)

        # Decrypt button
        dec_row = ctk.CTkFrame(inner, fg_color="transparent")
        dec_row.pack(fill="x", pady=(0, 12))

        dec_btn = self._make_accent_btn(
            dec_row, "Decrypt", self._decrypt_message, width=140, icon="🔓"
        )
        dec_btn.pack(side="left")
        Tooltip(dec_btn, "Decrypt using the selected mode", self)

        # Output
        self._make_sec_label(inner, "Decrypted output:").pack(anchor="w", pady=(0, 6))

        self._dec_output_frame = ctk.CTkFrame(
            inner, fg_color=c["surface2"], corner_radius=10, border_width=1,
            border_color=c["border"]
        )
        self._dec_output_frame.pack(fill="x")
        self._all_cards.append(self._dec_output_frame)

        self._dec_output_label = ctk.CTkLabel(
            self._dec_output_frame,
            text="No decrypted output yet",
            font=ctk.CTkFont(FONT_FAMILY, 14),
            text_color=c["text_sec"],
            wraplength=740,
            justify="left"
        )
        self._dec_output_label.pack(padx=16, pady=14, anchor="w")

        self._update_decrypt_toggle_style()

    def _update_decrypt_toggle_style(self):
        c = self.c
        mode = self._decrypt_mode.get()
        for btn, btn_mode in [(self._auto_btn, "auto"), (self._manual_btn, "manual")]:
            is_sel = (btn_mode == mode)
            btn.configure(
                fg_color=c["accent"] if is_sel else c["surface2"],
                hover_color=c["accent_dark"] if is_sel else c["border"],
                text_color=c["accent_text"] if is_sel else c["text"],
                border_color=c["accent"] if is_sel else c["border"],
                border_width=1
            )

    def _set_decrypt_mode(self, mode: str):
        self._decrypt_mode.set(mode)
        self._update_decrypt_toggle_style()
        if mode == "manual":
            self._manual_frame.pack(fill="x", pady=(0, 4))
        else:
            self._manual_frame.pack_forget()

    # ── Key Size Selection ───────────────────────────────────────────────────
    def _select_key_size(self, bits: int):
        self._key_bits = bits
        c = self.c
        for btn, b in self._key_btns:
            is_sel = (b == bits)
            btn.configure(
                fg_color=c["accent"] if is_sel else c["surface2"],
                hover_color=c["accent_dark"] if is_sel else c["border"],
                text_color=c["accent_text"] if is_sel else c["text"],
                border_color=c["accent"] if is_sel else c["border"]
            )

    # ── Key Generation ───────────────────────────────────────────────────────
    def _generate_keys(self):
        if self._generating:
            return
        self._generating = True
        self._gen_btn.configure(state="disabled", text="⚙  Generating…")
        self._set_status(f"Generating {self._key_bits}-bit RSA key pair…", "info")

        # Show progress bar
        self._gen_progress_label.configure(
            text=f"Generating {self._key_bits}-bit key pair, please wait…"
        )
        self._gen_progress_label.pack(side="left")
        self._gen_progress.pack(side="left", padx=(10, 0), fill="x", expand=True)
        self._gen_progress.start()

        threading.Thread(target=self._gen_keys_thread, daemon=True).start()

    def _gen_keys_thread(self):
        try:
            # Minimum visual delay for UX feedback
            t0 = time.time()
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self._key_bits,
            )
            elapsed = time.time() - t0
            if elapsed < 0.5:
                time.sleep(0.5 - elapsed)

            pub_pem = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            priv_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ).decode()

            self._private_key = private_key
            self._public_key = private_key.public_key()

            # Auto-save
            self._auto_save_keys(pub_pem, priv_pem)

            self.after(0, self._on_keys_generated, pub_pem, priv_pem)
        except Exception as e:
            self.after(0, self._on_gen_error, str(e))

    def _on_keys_generated(self, pub_pem: str, priv_pem: str):
        self._gen_progress.stop()
        self._gen_progress.pack_forget()
        self._gen_progress_label.pack_forget()

        self._set_textbox(self._pub_tb, pub_pem)
        self._set_textbox(self._priv_tb, priv_pem)

        self._key_size_label.configure(text=f"Key: {self._key_bits}-bit RSA")
        self._set_status(
            f"✓ {self._key_bits}-bit RSA key pair generated and saved to ~/Documents/RSA_Keys/",
            "success"
        )
        self._gen_btn.configure(state="normal", text="⚙  Generate Keys")
        self._generating = False

    def _on_gen_error(self, err: str):
        self._gen_progress.stop()
        self._gen_progress.pack_forget()
        self._gen_progress_label.pack_forget()
        self._gen_btn.configure(state="normal", text="⚙  Generate Keys")
        self._generating = False
        self._set_status(f"✗ Key generation failed: {err}", "error")

    def _auto_save_keys(self, pub_pem: str, priv_pem: str):
        try:
            save_dir = Path.home() / "Documents" / "RSA_Keys"
            save_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            (save_dir / f"public_key_{ts}.pem").write_text(pub_pem)
            (save_dir / f"private_key_{ts}.pem").write_text(priv_pem)
        except Exception:
            pass  # Non-fatal

    # ── Encryption ───────────────────────────────────────────────────────────
    def _encrypt_message(self):
        msg = self._msg_entry.get().strip()
        if not msg:
            self._set_status("✗ Please enter a message to encrypt.", "error")
            return
        if not self._public_key:
            self._set_status("✗ No public key loaded. Generate or import one first.", "error")
            return
        try:
            ct = self._public_key.encrypt(
                msg.encode("utf-8"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self._encrypted_data = ct
            b64 = base64.b64encode(ct).decode()
            self._set_textbox(self._enc_tb, b64)
            self._set_status("✓ Encryption successful — Base64 output ready.", "success")
        except Exception as e:
            self._set_status(f"✗ Encryption failed: {e}", "error")

    # ── Decryption ───────────────────────────────────────────────────────────
    def _decrypt_message(self):
        mode = self._decrypt_mode.get()
        try:
            if mode == "auto":
                if not self._private_key:
                    self._set_status("✗ No private key available. Generate keys first.", "error")
                    return
                if not self._encrypted_data:
                    self._set_status("✗ No encrypted data. Encrypt a message first.", "error")
                    return
                ct = self._encrypted_data
                priv = self._private_key
            else:
                enc_b64 = self._manual_enc_tb.get("1.0", "end").strip()
                priv_pem = self._manual_key_tb.get("1.0", "end").strip()
                if not enc_b64 or not priv_pem:
                    self._set_status("✗ Please provide both encrypted data and private key.", "error")
                    return
                ct = base64.b64decode(enc_b64)
                priv = serialization.load_pem_private_key(
                    priv_pem.encode(), password=None
                )

            plaintext = priv.decrypt(
                ct,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode("utf-8")

            self._show_dec_result(plaintext, success=True)
            self._set_status("✓ Decryption successful — original message restored.", "success")

        except Exception as e:
            self._show_dec_result(f"Decryption failed: {e}", success=False)
            self._set_status(f"✗ Decryption failed: {e}", "error")

    def _show_dec_result(self, text: str, success: bool):
        c = self.c
        bg = c["success_bg"] if success else c["error_bg"]
        fg = c["success_txt"] if success else c["error_txt"]
        icon = "✅" if success else "❌"
        self._dec_output_frame.configure(fg_color=bg, border_color=fg)
        self._dec_output_label.configure(
            text=f"{icon}  {text}", text_color=fg,
            font=ctk.CTkFont(FONT_FAMILY, 14, weight="bold" if success else "normal")
        )

    # ── Import / Export ──────────────────────────────────────────────────────
    def _import_public_key(self):
        path = filedialog.askopenfilename(
            title="Import Public Key",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            pem = Path(path).read_bytes()
            self._public_key = serialization.load_pem_public_key(pem)
            pem_str = Path(path).read_text()
            self._set_textbox(self._pub_tb, pem_str)
            self._set_status(f"✓ Public key imported from {Path(path).name}", "success")
        except Exception as e:
            self._set_status(f"✗ Failed to import public key: {e}", "error")

    def _export_keys(self):
        if not self._private_key and not self._public_key:
            self._set_status("✗ No keys to export. Generate keys first.", "error")
            return
        save_dir = filedialog.askdirectory(title="Select export folder")
        if not save_dir:
            return
        try:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            if self._public_key:
                pub_pem = self._public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                )
                (Path(save_dir) / f"public_key_{ts}.pem").write_bytes(pub_pem)
            if self._private_key:
                priv_pem = self._private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                )
                (Path(save_dir) / f"private_key_{ts}.pem").write_bytes(priv_pem)
            self._set_status(f"✓ Keys exported to {save_dir}", "success")
        except Exception as e:
            self._set_status(f"✗ Export failed: {e}", "error")

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _set_textbox(self, tb, text: str):
        tb.configure(state="normal")
        tb.delete("1.0", "end")
        tb.insert("1.0", text)
        tb.configure(state="disabled")

    def _copy_textbox(self, attr: str):
        tb = getattr(self, attr)
        tb.configure(state="normal")
        content = tb.get("1.0", "end").strip()
        tb.configure(state="disabled")
        if content:
            self.clipboard_clear()
            self.clipboard_append(content)
            self._set_status("✓ Copied to clipboard.", "info")

    def _clear_all(self):
        for tb in [self._pub_tb, self._priv_tb, self._enc_tb]:
            self._set_textbox(tb, "")
        self._msg_entry.delete(0, "end")
        self._dec_output_label.configure(
            text="No decrypted output yet",
            text_color=self.c["text_sec"],
            font=ctk.CTkFont(FONT_FAMILY, 14)
        )
        self._dec_output_frame.configure(
            fg_color=self.c["surface2"],
            border_color=self.c["border"]
        )
        self._private_key = None
        self._public_key = None
        self._encrypted_data = None
        self._key_size_label.configure(text="Key: None")
        self._set_status("All data cleared.", "info")

    def _set_status(self, msg: str, kind: str = "info"):
        icons = {"success": "✓", "error": "✗", "info": "ℹ"}
        colors = {
            "success": self.c["success_txt"],
            "error":   self.c["error_txt"],
            "info":    self.c["text_sec"]
        }
        self._status_label.configure(text=msg, text_color=colors.get(kind, self.c["text_sec"]))


# ── Entry Point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = RSAManagerApp()
    app.mainloop()
