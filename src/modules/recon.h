#pragma once

VOID collect_recon() {
    printf("\n===========PROCESSES===========\n");
    collect_processes();
    printf("\n===========USERS===========\n");
    collect_users_groups_shares();
    printf("\n===========NETWORK===========\n");
    collect_interfaces();
    printf("\n===========INTEGRITY===========\n");
    collect_integrity();  // this calls collect_installed_apps internally
};