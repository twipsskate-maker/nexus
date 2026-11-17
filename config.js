/* ใส่ค่า Client ID ของแอป Microsoft (Entra → App registrations → Application (client) ID) */
window.NEXUS_WEB_CONFIG = {
  clientId: '',
  // บัญชี Microsoft ส่วนตัว (outlook/hotmail/live) = 'consumers' • บัญชีองค์กร/โรงเรียน = 'organizations' • ทั้งสองแบบ = 'common'
  authority: 'consumers',
  folder: 'NEXUS-web'
};
