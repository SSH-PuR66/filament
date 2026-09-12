/* Pure install-state model shared by the UI and offline regression tests. */
(function (root, factory) {
  const model = factory();
  if (typeof module === "object" && module.exports) module.exports = model;
  else root.FilamentInstall = model;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  const DEVICE_MAX_AGE_MS = 15000;
  const CHECK_MAX_AGE_MS = 120000;

  function connection(state) {
    const device = state && state.device;
    if (!device || device.present !== true || typeof device.udid !== "string" || !device.udid)
      return null;
    return JSON.stringify([device.udid, device.version || "", device.connection || "",
      state.devmode && state.devmode.enabled === true]);
  }

  function fingerprint(input) {
    return JSON.stringify([String(input.app || "").trim(), input.use_identity === true,
      input.use_identity === true ? "" : String(input.profile || "").trim(),
      input.use_identity === true ? "" : String(input.p12 || "").trim(),
      input.use_identity === true ? "" : String(input.p12password || "")]);
  }

  function createGate() {
    let revision = 0, checked = null, deviceKey = null, deviceAt = -Infinity;
    function invalidate() { revision++; checked = null; }
    return {
      invalidate,
      observe(state, now) {
        const next = connection(state);
        if (next !== deviceKey || next === null) invalidate();
        deviceKey = next;
        deviceAt = now;
      },
      begin(input, now) {
        invalidate();
        return {revision, input: fingerprint(input), deviceKey, started: now};
      },
      finish(ticket, ok, input, now) {
        if (ticket.revision !== revision || ticket.input !== fingerprint(input)
            || ticket.deviceKey !== deviceKey || !deviceKey || ok !== true
            || now < ticket.started || now - ticket.started > CHECK_MAX_AGE_MS
            || now - deviceAt > DEVICE_MAX_AGE_MS) return false;
        checked = {input: ticket.input, deviceKey, at: now};
        return true;
      },
      canInstall(input, now) {
        return !!(checked && deviceKey && checked.deviceKey === deviceKey
          && checked.input === fingerprint(input) && now >= checked.at
          && now >= deviceAt && now - checked.at <= CHECK_MAX_AGE_MS
          && now - deviceAt <= DEVICE_MAX_AGE_MS);
      }
    };
  }

  function setup(state, signing) {
    const device = (state && state.device) || {};
    const present = device.present === true;
    const devmode = state && state.devmode && state.devmode.enabled;
    const olderIOS = /^15(?:\.|$)/.test(String(device.version || ""));
    const ready = signing && signing.ready === true;
    const reasons = signing && Array.isArray(signing.blockers) ? signing.blockers : [];
    return [
      {title: "Connect your iPhone", status: present ? "ready" : state ? "action" : "unknown",
        detail: present ? "Device detected. Keep the cable connected during installation."
          : "Connect a data cable, unlock the phone and accept Trust This Computer. Re-check after reconnecting."},
      {title: "Prepare Developer Mode", status: !present ? "waiting"
          : olderIOS || devmode === true ? "ready" : devmode === false ? "action" : "unknown",
        detail: !present ? "Waiting for the device connection."
          : olderIOS ? "iOS 15 does not have the Developer Mode switch."
          : devmode === true ? "Developer Mode is on."
          : "Settings > Privacy & Security > Developer Mode. Complete the restart and confirm Turn On on the phone."},
      {title: "Check configured signing identity", status: !signing ? "unknown" : ready ? "ready" : "action",
        detail: !signing ? "Select Re-check setup to inspect the local certificate and profile."
          : ready ? "Local identity checks passed. The selected app still needs its own preflight."
          : reasons.length ? reasons.join(" · ") : "Signing readiness could not be verified."}
    ];
  }

  return {createGate, fingerprint, setup, DEVICE_MAX_AGE_MS, CHECK_MAX_AGE_MS};
});
