from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    name = "domaindump"
    description = "Dumps domain info such as Users, Computers, Groups, Trusts and etc."
    supported_protocols = ["ldap"]


    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):
        def pc_dump():
            resp = connection.search(
                searchFilter="(objectCategory=computer)",
                attributes=["sAMAccountName"]
            )
            resp_parsed = parse_result_attributes(resp)
            computers = []
            for computer in resp_parsed:
                host_name = computer["sAMAccountName"]

                comp = f"Domain computer: {host_name}\n"
                computers.append(comp)


            try:
                with open("domain_computers.txt", "w") as file:
                    file.write("\n".join(computers)+"\n")
                context.log.success("Results saved to domain_computers.txt!\n")
            except Exception as e:
                print(f"Error: {e}")

        def users_dump():
            resp = connection.search(
                searchFilter="(&(objectCategory=person)(objectClass=user))",
                attributes=["sAMAccountName", "objectSid"]
            )

            resp_parsed = parse_result_attributes(resp)
            users = []

            for user in resp_parsed:
                username = user["sAMAccountName"]
                sid = user.get("objectSid")

                ad_user = f"sAMAccountName: {username}\nobjectSid: {sid}\n"
                users.append(ad_user)

            try:
                with open("domain_users.txt", "w") as file:
                    file.write("\n".join(users)+"\n")
                context.log.success("Results saved to domain_users.txt!\n")
            except Exception as e:
                print(f"Error: {e}")


        def trusts_dump():
            resp = connection.search(
                searchFilter="(objectCategory=trustedDomain)",
                attributes=["Direction", "Name", "DomainSid", "NetBiosName"]
            )
            resp_parsed = parse_result_attributes(resp)
            trusts = []

            for trust in resp_parsed:
                direction = trust["Direction"]
                name = trust.get("Name")
                domain_sid = trust.get("DomainSid")
                nbname = trust.get("NetBiosName")

                ad_trust = f"Direction: {direction}\nName: {name}\nDomainSID: {domain_sid}\nNetBiosName: {nbname}\n"
                trusts.append(ad_trust)

            try:
                with open("domain_trusts.txt", "w") as file:
                    file.write("\n".join(trusts)+"\n")
                context.log.success("Results saved to domain_trusts.txt!\n")
            except Exception as e:
                print(f"Error: {e}\n")


        def groups_dump():
            resp = connection.search(
                searchFilter="(objectCategory=group)",
                attributes=["sAMAccountName", "groupType"]
            )
            resp_parsed = parse_result_attributes(resp)
            groups = []

            for group in resp_parsed:
                name = group["sAMAccountName"]
                type = group.get("groupType")


                ad_group = f"sAMAccountName: {name}\ngroupType: {type}\n"
                groups.append(ad_group)

            try:
                with open("domain_groups.txt", "w") as file:
                    file.write("\n".join(groups)+"\n")
                context.log.success("Results saved to domain_groups.txt!\n")
            except Exception as e:
                print(f"Error: {e}\n")

        def admins_dump():
            resp = connection.search(
                searchFilter="(&(objectCategory=group)(sAMAccountName=Domain Admins))",
                attributes=["member"]
            )
            resp_parsed = parse_result_attributes(resp)

            admins = []

            for admin in resp_parsed:
                member = admin["member"]

                ad_admin = f"Domain admin: {member}\n"
                admins.append(ad_admin)


            try:
                with open("domain_admins.txt", "w") as file:
                    file.write("\n".join(admins)+"\n")
                context.log.success("Results saved to domain_admins.txt!\b")
            except Exception as e:
                print(f"Error: {e}\n")


        def dump_locked_accounts():
            resp = connection.search(
                searchFilter="(&(objectClass=person)(objectClass=user)(lockoutTime>=1))",
                attributes=["sAMAccountName"]
            )
            resp_parsed = parse_result_attributes(resp)

            locked_accs = []

            for account in resp_parsed:
                name = account["sAMAccountName"]

                ad_locked_account = f"Locked account: {name}\n"

                locked_accs.append(ad_locked_account)

            try:
                with open("domain_locked_accounts.txt", "w") as file:
                    file.write("\n".join(locked_accs)+"\n")
                context.log.success("Results saved to domain_locked_accounts.txt!\n")
            except Exception as e:
                print(f"Error: {e}")


        def dump_dcs():
            resp = connection.search(
                searchFilter="(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                attributes=["distinguishedName"]
            )
            resp_parsed = parse_result_attributes(resp)

            dc_comps = []

            for pc in resp_parsed:
                member = pc["distinguishedName"]

                dc_pc = f"Domain Controller: {member}\n"

                dc_comps.append(dc_pc)

            try:
                with open("domain_controllers.txt", "w") as file:
                    file.write("\n".join(dc_comps)+"\n")
                context.log.success("Results saved to domain_controllers.txt!\n")
            except Exception as e:
                print(f"Error: {e}")

        def rdu_dump():
            resp = connection.search(
                searchFilter="(&(objectCategory=group)(sAMAccountName=Remote Desktop Users))",
                attributes=["member"]
            )
            resp_parsed = parse_result_attributes(resp)

            rdu_group = []

            for user in resp_parsed:
                rdu = user['member']

                rdu = f"Remote Desktop User: {rdu}\n"

                rdu_group.append(rdu)

            try:
                with open("domain_rds_users.txt", "w") as file:
                    file.write("\n".join(rdu_group)+"\n")
                context.log.success("Results saved to domain_rds_users.txt!\n")
            except Exception as e:
                print(f"Error: {e}\n")

 

        pc_dump()
        users_dump()
        groups_dump()
        admins_dump()
        trusts_dump()
        dump_locked_accounts()
        dump_dcs()
        rdu_dump()

        

