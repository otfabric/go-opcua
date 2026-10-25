#!/usr/bin/env bash
#
# Downloads the latest OPC UA schema files from the OPC Foundation GitHub repository
# (default branch "latest") into the schema directory. Opc.Ua.NodeSet2.xml goes to
# internal/schema/, where it is embedded. Run manually when the spec is updated:
#
#   ./schema/update-schema.sh
#
# After downloading, regenerate code with: make gen

set -o errexit
set -o nounset
set -o pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_dir=$(cd "${script_dir}/.." && pwd)

echo "Downloading NodeIds.csv"
wget -nv https://raw.githubusercontent.com/OPCFoundation/UA-Nodeset/latest/Schema/NodeIds.csv -O "${script_dir}/NodeIds.csv"

echo "Downloading StatusCode.csv"
wget -nv https://raw.githubusercontent.com/OPCFoundation/UA-Nodeset/latest/Schema/StatusCode.csv -O "${script_dir}/StatusCode.csv"

echo "Downloading AttributeIds.csv"
wget -nv https://raw.githubusercontent.com/OPCFoundation/UA-Nodeset/latest/Schema/AttributeIds.csv -O "${script_dir}/AttributeIds.csv"

echo "Downloading ServerCapabilities.csv"
wget -nv https://raw.githubusercontent.com/OPCFoundation/UA-Nodeset/latest/Schema/ServerCapabilities.csv -O "${script_dir}/ServerCapabilities.csv"

echo "Downloading Opc.Ua.NodeIds.permissions.csv"
wget -nv https://raw.githubusercontent.com/OPCFoundation/UA-Nodeset/latest/Schema/Opc.Ua.NodeIds.permissions.csv -O "${script_dir}/Opc.Ua.NodeIds.permissions.csv"

echo "Downloading Opc.Ua.Types.bsd"
wget -nv https://raw.githubusercontent.com/OPCFoundation/UA-Nodeset/latest/Schema/Opc.Ua.Types.bsd -O "${script_dir}/Opc.Ua.Types.bsd"

echo "Downloading Opc.Ua.NodeSet2.xml"
wget -nv https://raw.githubusercontent.com/OPCFoundation/UA-Nodeset/latest/Schema/Opc.Ua.NodeSet2.xml -O "${repo_dir}/internal/schema/Opc.Ua.NodeSet2.xml"

echo "Downloading Opc.Ua.PredefinedNodes.xml"
wget -nv https://raw.githubusercontent.com/OPCFoundation/UA-Nodeset/latest/DotNet/Opc.Ua.PredefinedNodes.xml -O "${script_dir}/Opc.Ua.PredefinedNodes.xml"

echo "Downloading Opc.Ua.Gds.NodeIds.csv"
wget -nv https://raw.githubusercontent.com/OPCFoundation/UA-Nodeset/latest/GDS/Opc.Ua.Gds.NodeIds.csv -O "${script_dir}/Opc.Ua.Gds.NodeIds.csv"

echo "Downloading Opc.Ua.Gds.NodeSet2.xml"
wget -nv https://raw.githubusercontent.com/OPCFoundation/UA-Nodeset/latest/GDS/Opc.Ua.Gds.NodeSet2.xml -O "${repo_dir}/internal/schema/Opc.Ua.Gds.NodeSet2.xml"
